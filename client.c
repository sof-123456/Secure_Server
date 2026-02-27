#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/kdf.h> 

#define PORT 1112
#define BUF 2048

int send_all(int fd,  uint8_t  * buf, int len){
    int total=0; 
    while(total<len){
        int s=send(fd,buf+total,len-total,0);
        if(s<=0) return -1; 
        total+=s;
    } return total;
}

int recv_all(int fd,   uint8_t * buf, int len){
    int total=0; while(total<len){
        int r=recv(fd,buf+total,len-total,0);
        if(r<=0) return -1; total+=r;
    } return total;
}

EVP_PKEY* load_key(const char* file,int priv){
    FILE* f=fopen(file,"r"); if(!f) return NULL;
    EVP_PKEY* k= priv ? PEM_read_PrivateKey(f,NULL,NULL,NULL) : PEM_read_PUBKEY(f,NULL,NULL,NULL);
    fclose(f); return k;
}

EVP_PKEY* gen_x25519(){
    EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_X25519,NULL);
    EVP_PKEY *pkey=NULL; EVP_PKEY_keygen_init(ctx); EVP_PKEY_keygen(ctx,&pkey);
    EVP_PKEY_CTX_free(ctx); 
    return pkey;
}

int derive_secret(EVP_PKEY* priv, EVP_PKEY* peer, uint8_t * out){
    EVP_PKEY_CTX* ctx=EVP_PKEY_CTX_new(priv,NULL); 
    size_t len=32;
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx,peer);
    EVP_PKEY_derive(ctx,out,&len);
    EVP_PKEY_CTX_free(ctx);
    
    return (int)len;
}
//RNG  --Entropy check 
// --- HKDF & AES-GCM Logic (Must Match Server) ---
int derive_modern_hkdf(const unsigned char *secret, size_t secret_len, 
                       const unsigned char *salt, size_t salt_len,
                       unsigned char *out, size_t out_len) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[5], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    *p++ = OSSL_PARAM_construct_octet_string("key", (void *)secret, secret_len);
    *p++ = OSSL_PARAM_construct_octet_string("salt", (void *)salt, salt_len);
    *p++ = OSSL_PARAM_construct_octet_string("info", "MySecureApp-v1", 14);
    *p = OSSL_PARAM_construct_end();
    int ret = (EVP_KDF_derive(kctx, out, out_len, params) > 0) ? 0 : -1;
    EVP_KDF_CTX_free(kctx); 
    EVP_KDF_free(kdf); 
    return ret;
}

int encrypt_msg_with_seq(uint8_t  * key, uint8_t * pt, int plen,
                        uint8_t*  fixed_nonce, uint64_t seq_num, 
                        uint8_t * ct, uint8_t * tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len, clen; unsigned char iv[12];
    memcpy(iv, fixed_nonce, 4);
    for (int i = 0; i < 8; i++)   
         iv[4 + i] = (seq_num >> (56 - (i * 8))) & 0xFF;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ct, &len, pt, plen); clen = len;
    EVP_EncryptFinal_ex(ctx, ct + len, &len); clen += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx); return clen;
}

int decrypt_msg_with_seq(uint8_t * key, uint8_t* ct, int clen,
                        uint8_t * fixed_nonce, uint64_t seq_num, 
                        uint8_t * tag, uint8_t * pt) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len, plen; unsigned char iv[12];
    memcpy(iv, fixed_nonce, 4);
    for (int i = 0; i < 8; i++) 
        iv[4 + i] = (seq_num >> (56 - (i * 8))) & 0xFF;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, pt, &len, ct, clen); plen = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    int res = EVP_DecryptFinal_ex(ctx, pt + len, &len);
    EVP_CIPHER_CTX_free(ctx); 
    return (res > 0) ? (plen + len) : -1;
}

int main(){
    EVP_PKEY* client_priv = load_key("client_priv.pem", 1);
    EVP_PKEY* server_pub = load_key("server_pub.pem", 0);
    if (!client_priv || !server_pub) { printf("Key load failed\n"); return 1; }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    connect(s, (void*)&a, sizeof(a));

    // --- Handshake ---
    EVP_PKEY* client_eph = gen_x25519();
    unsigned char client_raw[32]; size_t l=32;
    EVP_PKEY_get_raw_public_key(client_eph, client_raw, &l);
    send_all(s, client_raw, 32);

    unsigned char server_raw[32], server_sig[64];
    recv_all(s, server_raw, 32);
    EVP_PKEY* server_eph = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, server_raw, 32);

    unsigned char transcript[64];
    memcpy(transcript, client_raw, 32); 
    memcpy(transcript+32, server_raw, 32);

    recv_all(s, server_sig, 64);

    EVP_MD_CTX* v = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(v, NULL, NULL, NULL, server_pub);
    if(EVP_DigestVerify(v, server_sig, 64, transcript, 64) <= 0) { printf("Server Auth Fail\n"); return 1; }
    EVP_MD_CTX_free(v);

    unsigned char client_sig[64];
    size_t siglen=64;
    EVP_MD_CTX* m = EVP_MD_CTX_new();
    EVP_DigestSignInit(m, NULL, NULL, NULL, client_priv);
    EVP_DigestSign(m, client_sig, &siglen, transcript, 64);
    send_all(s, client_sig, 64);
    EVP_MD_CTX_free(m);

    // --- Secure Channel Init ---
    unsigned char secret[32], key[32], fixed_nonce[4], key_material[36];
;
    derive_secret(client_eph, server_eph, secret);
    derive_modern_hkdf(secret, 32, transcript, 64, key_material, 36);   // 36 byte  
    memcpy(key, key_material, 32); 
    memcpy(fixed_nonce, key_material  + 32, 4);

    printf("Secure channel established.\n");

        uint64_t send_seq = 0;

        unsigned char tag[16], ct[BUF], pt[BUF];
        int plen, clen;

        // 1. SEND
        printf("Client > ");
        if(!fgets((char*)pt, BUF, stdin)) {
            close(s);
            return 0;
        }       
        
        plen = strlen((char*)pt);

        clen = encrypt_msg_with_seq(key, pt, plen, fixed_nonce, send_seq, ct, tag);

        // --- Send sequence + ciphertext + tag ---
        uint64_t seq = send_seq++;
        unsigned char seq_buf[8];
        for (int i=0;i<8;i++)
            seq_buf[i] = (seq >> (56 - i*8)) & 0xFF;

        uint32_t net_len = htonl(clen); // ciphertext
        send_all(s, seq_buf, 8);
        send_all(s, (uint8_t*)&net_len, 4);
        send_all(s, ct, clen);
        send_all(s, tag, 16);


        OPENSSL_cleanse(secret, sizeof(secret));
        OPENSSL_cleanse(key_material, sizeof(key_material));
        OPENSSL_cleanse(key, sizeof(key));
        EVP_PKEY_free(client_priv);
        EVP_PKEY_free(server_pub);
        EVP_PKEY_free(client_eph);
        EVP_PKEY_free(server_eph);


    close(s);
    return 0;
}
