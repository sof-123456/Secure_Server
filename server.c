#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#define PORT 4444
#define BUF 2048
#define ROUNDS 30   // Number of send/recv rounds

int read_all(int fd, unsigned char *buf, int len) {
    int total = 0;
    while (total < len) {
        int r = read(fd, buf + total, len - total);
        if (r <= 0) return -1;
        total += r;
    }
    return total;
}

int write_all(int fd, unsigned char *buf, int len) {
    int total = 0;
    while (total < len) {
        int r = write(fd, buf + total, len - total);
        if (r <= 0) return -1;
        total += r;
    }
    return total;
}

int main() {
    int s, c;
    struct sockaddr_in addr;
    unsigned char buf[BUF];

    s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("Bind"); return 1; }
    listen(s, 1);
    printf("[+] Server listening...\n");

    c = accept(s, NULL, NULL);
    printf("[+] Client connected!\n");

    // --- DH key exchange ---
    DH *dh = DH_get_2048_256();
    DH_generate_key(dh);
    const BIGNUM *pub = NULL;
    DH_get0_key(dh, &pub, NULL);
    int pub_len = BN_num_bytes(pub);
    BN_bn2bin(pub, buf);
    int nlen = htonl(pub_len);
    write_all(c, (unsigned char*)&nlen, sizeof(nlen));
    write_all(c, buf, pub_len);

    int clen;
    read_all(c, (unsigned char*)&clen, sizeof(clen));
    clen = ntohl(clen);
    read_all(c, buf, clen);
    BIGNUM *client_pub = BN_bin2bn(buf, clen, NULL);

    unsigned char secret[256], key[32];
    int secret_len = DH_compute_key(secret, client_pub, dh);
    SHA256(secret, secret_len, key);

    DH_free(dh);
    BN_free(client_pub);

    unsigned char iv[12], tag[16], ciphertext[BUF], plaintext[BUF];
    int ct_len, outlen, final_len;

    for (int i = 0; i < ROUNDS; i++) {
        // --- RECEIVE message from client ---
        read_all(c, iv, 12);
        read_all(c, (unsigned char*)&ct_len, sizeof(ct_len));
        ct_len = ntohl(ct_len);
        read_all(c, ciphertext, ct_len);
        read_all(c, tag, 16);

        EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(d_ctx, EVP_aes_256_gcm(), NULL, key, iv);
        EVP_DecryptUpdate(d_ctx, plaintext, &outlen, ciphertext, ct_len);
        EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
        EVP_DecryptFinal_ex(d_ctx, plaintext + outlen, &final_len);
        EVP_CIPHER_CTX_free(d_ctx);
        plaintext[outlen + final_len] = 0;

        printf("Client: %s\n", plaintext);

        // --- SEND reply to client ---
        snprintf((char*)plaintext, BUF, "Server reply %d", i + 1);
        RAND_bytes(iv, 12);
        EVP_CIPHER_CTX *e_ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(e_ctx, EVP_aes_256_gcm(), NULL, key, iv);
        EVP_EncryptUpdate(e_ctx, ciphertext, &outlen, plaintext, strlen((char*)plaintext));
        EVP_EncryptFinal_ex(e_ctx, ciphertext + outlen, &final_len);
        EVP_CIPHER_CTX_ctrl(e_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

        int nct_len = htonl(outlen + final_len);
        write_all(c, iv, 12);
        write_all(c, (unsigned char*)&nct_len, sizeof(nct_len));
        write_all(c, ciphertext, outlen + final_len);
        write_all(c, tag, 16);
        EVP_CIPHER_CTX_free(e_ctx);
    }

    printf("[+] Server done. Closing.\n");
    close(c);
    close(s);
    return 0;
}


#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/ed25519.h>

#define PORT 4444
#define BUF 2048
#define ROUNDS 5 // number of message exchanges

int read_all(int fd, unsigned char *buf, int len) {
    int total = 0;
    while (total < len) {
        int r = read(fd, buf + total, len - total);
        if (r <= 0) return -1;
        total += r;
    }
    return total;
}

int write_all(int fd, unsigned char *buf, int len) {
    int total = 0;
    while (total < len) {
        int r = write(fd, buf + total, len - total);
        if (r <= 0) return -1;
        total += r;
    }
    return total;
}

int main() {
    int s, c;
    struct sockaddr_in addr;
    unsigned char buf[BUF];

    // --- Load client public key ---
    unsigned char client_pk[32];
    FILE *f = fopen("client_ed25519_pk.bin","rb");
    if(!f){ perror("client public key"); return 1; }
    fread(client_pk,1,32,f); fclose(f);

    // --- Load server private key ---
    unsigned char server_sk[64];
    f = fopen("server_ed25519_sk.bin","rb");
    if(!f){ perror("server private key"); return 1; }
    fread(server_sk,1,64,f); fclose(f);

    // --- Setup server socket ---
    s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if(bind(s,(struct sockaddr*)&addr,sizeof(addr))<0){ perror("Bind"); return 1; }
    listen(s,1);
    printf("[+] Server listening...\n");

    c = accept(s,NULL,NULL);
    printf("[+] Client connected!\n");

    // --- Diffie-Hellman key exchange ---
    DH *dh = DH_get_2048_256();
    DH_generate_key(dh);
    const BIGNUM *pub = NULL;
    DH_get0_key(dh,&pub,NULL);

    int pub_len = BN_num_bytes(pub);
    BN_bn2bin(pub,buf);
    int nlen = htonl(pub_len);
    write_all(c,(unsigned char*)&nlen,sizeof(nlen));
    write_all(c,buf,pub_len);

    int clen;
    read_all(c,(unsigned char*)&clen,sizeof(clen));
    clen = ntohl(clen);
    read_all(c,buf,clen);
    BIGNUM *client_pub = BN_bin2bn(buf,clen,NULL);

    unsigned char secret[256], key[32];
    int secret_len = DH_compute_key(secret,client_pub,dh);
    SHA256(secret,secret_len,key);

    DH_free(dh);
    BN_free(client_pub);

    unsigned char iv[12], tag[16], ciphertext[BUF], plaintext[BUF];
    int ct_len, outlen, final_len;

    for(int i=0;i<ROUNDS;i++){
        // --- Receive message ---
        if(read_all(c,iv,12)<=0) break;
        if(read_all(c,(unsigned char*)&ct_len,sizeof(ct_len))<=0) break;
        ct_len = ntohl(ct_len);
        if(read_all(c,ciphertext,ct_len)<=0) break;

        unsigned char sig[64];
        if(read_all(c,sig,64)<=0) break;
        if(read_all(c,tag,16)<=0) break;

        // --- Decrypt ---
        EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(d_ctx,EVP_aes_256_gcm(),NULL,key,iv);
        EVP_DecryptUpdate(d_ctx,plaintext,&outlen,ciphertext,ct_len);
        EVP_CIPHER_CTX_ctrl(d_ctx,EVP_CTRL_GCM_SET_TAG,16,tag);
        if(EVP_DecryptFinal_ex(d_ctx,plaintext+outlen,&final_len)<=0){
            printf("[-] Decryption failed\n");
            EVP_CIPHER_CTX_free(d_ctx); break;
        }
        EVP_CIPHER_CTX_free(d_ctx);
        plaintext[outlen+final_len]=0;

        // --- Verify client signature ---
        if(!ED25519_verify(plaintext,outlen+final_len,sig,client_pk)){
            printf("[-] Client signature invalid!\n"); break;
        }

        printf("[Client verified]: %s\n",plaintext);

        // --- Send server reply ---
        snprintf((char*)plaintext,BUF,"Server reply %d",i+1);
        RAND_bytes(iv,12);
        EVP_CIPHER_CTX *e_ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(e_ctx,EVP_aes_256_gcm(),NULL,key,iv);
        EVP_EncryptUpdate(e_ctx,ciphertext,&outlen,plaintext,strlen((char*)plaintext));
        EVP_EncryptFinal_ex(e_ctx,ciphertext+outlen,&final_len);
        EVP_CIPHER_CTX_ctrl(e_ctx,EVP_CTRL_GCM_GET_TAG,16,tag);

        // --- Sign plaintext ---
        unsigned char server_sig[64];
        ED25519_sign(server_sig,plaintext,strlen((char*)plaintext),server_sk);

        int nct_len = htonl(outlen+final_len);
        write_all(c,iv,12);
        write_all(c,(unsigned char*)&nct_len,sizeof(nct_len));
        write_all(c,ciphertext,outlen+final_len);
        write_all(c,server_sig,64);
        write_all(c,tag,16);
        EVP_CIPHER_CTX_free(e_ctx);
    }

    printf("[+] Server done. Closing.\n");
    close(c);
    close(s);
    return 0;
}
