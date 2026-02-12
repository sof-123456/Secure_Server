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
#define ROUNDS 3

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
    int s;
    struct sockaddr_in addr;
    unsigned char buf[BUF];

    s = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    connect(s, (struct sockaddr*)&addr, sizeof(addr));
    printf("[+] Connected to server.\n");

    // --- DH key exchange ---
    DH *dh = DH_get_2048_256();
    DH_generate_key(dh);
    const BIGNUM *pub = NULL;
    DH_get0_key(dh, &pub, NULL);
    int pub_len = BN_num_bytes(pub);
    BN_bn2bin(pub, buf);
    int nlen = htonl(pub_len);
    write_all(s, (unsigned char*)&nlen, sizeof(nlen));
    write_all(s, buf, pub_len);

    int slen;
    read_all(s, (unsigned char*)&slen, sizeof(slen));
    slen = ntohl(slen);
    read_all(s, buf, slen);
    BIGNUM *server_pub = BN_bin2bn(buf, slen, NULL);

    unsigned char secret[256], key[32];
    int secret_len = DH_compute_key(secret, server_pub, dh);
    SHA256(secret, secret_len, key);

    DH_free(dh);
    BN_free(server_pub);

    unsigned char iv[12], tag[16], ciphertext[BUF], plaintext[BUF];
    int ct_len, outlen, final_len;

    for (int i = 0; i < ROUNDS; i++) {
        // --- Send message ---
        printf("Client > ");
        fgets((char*)plaintext, BUF, stdin);
        plaintext[strcspn((char*)plaintext, "\n")] = 0;

        RAND_bytes(iv, 12);
        EVP_CIPHER_CTX *e_ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(e_ctx, EVP_aes_256_gcm(), NULL, key, iv);
        EVP_EncryptUpdate(e_ctx, ciphertext, &outlen, plaintext, strlen((char*)plaintext));
        EVP_EncryptFinal_ex(e_ctx, ciphertext + outlen, &final_len);
        EVP_CIPHER_CTX_ctrl(e_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

        int nct_len = htonl(outlen + final_len);
        write_all(s, iv, 12);
        write_all(s, (unsigned char*)&nct_len, sizeof(nct_len));
        write_all(s, ciphertext, outlen + final_len);
        write_all(s, tag, 16);
        EVP_CIPHER_CTX_free(e_ctx);

        // --- Receive server reply ---
        read_all(s, iv, 12);
        read_all(s, (unsigned char*)&ct_len, sizeof(ct_len));
        ct_len = ntohl(ct_len);
        read_all(s, ciphertext, ct_len);
        read_all(s, tag, 16);

        EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(d_ctx, EVP_aes_256_gcm(), NULL, key, iv);
        EVP_DecryptUpdate(d_ctx, plaintext, &outlen, ciphertext, ct_len);
        EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
        EVP_DecryptFinal_ex(d_ctx, plaintext + outlen, &final_len);
        EVP_CIPHER_CTX_free(d_ctx);

        plaintext[outlen + final_len] = 0;
        printf("Server: %s\n", plaintext);
    }

    printf("[+] Done. Closing connection.\n");
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
#define ROUNDS 5

int read_all(int fd, unsigned char *buf, int len) {
    int total=0;
    while(total<len){
        int r=read(fd,buf+total,len-total);
        if(r<=0) return -1;
        total+=r;
    }
    return total;
}

int write_all(int fd, unsigned char *buf, int len){
    int total=0;
    while(total<len){
        int r=write(fd,buf+total,len-total);
        if(r<=0) return -1;
        total+=r;
    }
    return total;
}

int main(){
    int s;
    struct sockaddr_in addr;
    unsigned char buf[BUF];

    // --- Load client private key ---
    unsigned char client_sk[64];
    FILE *f = fopen("client_ed25519_sk.bin","rb");
    if(!f){ perror("client_sk"); return 1; }
    fread(client_sk,1,64,f); fclose(f);

    // --- Load server public key ---
    unsigned char server_pk[32];
    f = fopen("server_ed25519_pk.bin","rb");
    if(!f){ perror("server_pk"); return 1; }
    fread(server_pk,1,32,f); fclose(f);

    // --- Connect to server ---
    s = socket(AF_INET, SOCK_STREAM,0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if(connect(s,(struct sockaddr*)&addr,sizeof(addr))<0){ perror("connect"); return 1; }

    // --- DH key exchange ---
    int slen;
    read_all(s,&slen,sizeof(slen));
    slen = ntohl(slen);
    read_all(s,buf,slen);
    BIGNUM *server_pub = BN_bin2bn(buf,slen,NULL);

    DH *dh = DH_get_2048_256();
    DH_generate_key(dh);
    const BIGNUM *pub = NULL;
    DH_get0_key(dh,&pub,NULL);

    int pub_len = BN_num_bytes(pub);
    BN_bn2bin(pub,buf);
    int nlen = htonl(pub_len);
    write_all(s,(unsigned char*)&nlen,sizeof(nlen));
    write_all(s,buf,pub_len);

    unsigned char secret[256], key[32];
    int secret_len = DH_compute_key(secret,server_pub,dh);
    SHA256(secret,secret_len,key);

    DH_free(dh); BN_free(server_pub);

    unsigned char iv[12], tag[16], ciphertext[BUF], plaintext[BUF];
    int ct_len, outlen, final_len;

    for(int i=0;i<ROUNDS;i++){
        // --- Send message ---
