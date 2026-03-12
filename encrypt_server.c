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
#define PORT_CLIENT 1113
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
        if(r<=0) 
           return -1;
        total+=r;
    }
     return total;
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


int main(){
    EVP_PKEY* client_priv = load_key("client_priv.pem", 1);
    EVP_PKEY* server_pub = load_key("server_pub.pem", 0);
    if (!client_priv || !server_pub) { printf("Key load failed\n"); return 1; }

    int s_decrypt = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; a.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    connect(s_decrypt, (void*)&a, sizeof(a));

    // --- Handshake ---
    EVP_PKEY* client_eph = gen_x25519();
    unsigned char client_raw[32]; size_t l=32;
    EVP_PKEY_get_raw_public_key(client_eph, client_raw, &l);
    send_all(s_decrypt, client_raw, 32);

    unsigned char server_raw[32], server_sig[64];
    recv_all(s_decrypt, server_raw, 32);
    EVP_PKEY* server_eph = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, server_raw, 32);

    unsigned char transcript[64];
    memcpy(transcript, client_raw, 32); 
    memcpy(transcript+32, server_raw, 32);

    recv_all(s_decrypt, server_sig, 64);

    EVP_MD_CTX* v = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(v, NULL, NULL, NULL, server_pub);
    if(EVP_DigestVerify(v, server_sig, 64, transcript, 64) <= 0) { printf("Server Auth Fail\n"); return 1; }
    EVP_MD_CTX_free(v);

    unsigned char client_sig[64];
    size_t siglen=64;
    EVP_MD_CTX* m = EVP_MD_CTX_new();
    EVP_DigestSignInit(m, NULL, NULL, NULL, client_priv);
    EVP_DigestSign(m, client_sig, &siglen, transcript, 64);
    send_all(s_decrypt, client_sig, 64);
    EVP_MD_CTX_free(m);

    // --- Secure Channel Init ---
    unsigned char secret[32], key[32], fixed_nonce[4], key_material[36];

    derive_secret(client_eph, server_eph, secret);
    derive_modern_hkdf(secret, 32, transcript, 64, key_material, 36);   // 36 byte  
    memcpy(key, key_material, 32); 
    memcpy(fixed_nonce, key_material + 32, 4);


    printf("[Proxy] Secure channel to Server established.\n");

    // 2. PREPARE PROXY: Listen for Program 1
    int s_listen = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(s_listen, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in proxy_addr = {0};
    proxy_addr.sin_family = AF_INET; 
    proxy_addr.sin_port = htons(PORT_CLIENT); // PORT 1113
    proxy_addr.sin_addr.s_addr = INADDR_ANY;
    bind(s_listen, (void*)&proxy_addr, sizeof(proxy_addr)); 
    listen(s_listen, 5);

    uint64_t send_seq = 0;
    unsigned char pt[BUF], ct[BUF], tag[16];

    // 3. MAIN LOOP: Stay alive to bridge messages
    
        printf("\n[Proxy] Waiting for plaintext from Program 1...\n");

        int c_client = accept(s_listen, NULL, NULL);
        if (c_client < 0)  return 0;

        // Read the plaintext
        int received = recv(c_client, pt, BUF, 0); 
        if (received > 0) {
            printf("[Proxy] Received %d bytes. Encrypting...\n", received);
            
            // Encrypt
            int clen = encrypt_msg_with_seq(key, pt, received, fixed_nonce, send_seq, ct, tag);

            // Send structured packet to Program 3
            uint32_t net_len = htonl(clen);
            uint64_t seq_out = send_seq++;
            unsigned char seq_buf[8];
            for (int i=0; i<8; i++)
                seq_buf[i] = (seq_out >> (56 - i*8)) & 0xFF;

            send_all(s_decrypt, seq_buf, 8);
            send_all(s_decrypt, (uint8_t*)&net_len, 4);
            send_all(s_decrypt, ct, clen);
            send_all(s_decrypt, tag, 16);

            printf("[Proxy] Forwarded encrypted data to Decrypt Server.\n");
        }
        close(c_client); // Close connection to Program 1, but KEEP connection to Program 3 open

    // This part is only reached if the loop breaks
    close(s_decrypt);
    return 0;
}
