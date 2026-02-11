#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/dh.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h> // Fixed: Required for RAND_bytes

#define PORT 4444
#define BUF 2048

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
    struct sockaddr_in a;
    unsigned char buf[BUF];
    unsigned char key[32]; // Shared key variable

    s = socket(AF_INET, SOCK_STREAM, 0);
    a.sin_family = AF_INET;
    a.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);

    if (connect(s, (void*)&a, sizeof(a)) < 0) {
        perror("[-] Connection failed");
        return 1;
    }
    printf("[+] Connected to server\n");

    /* ---------- Receive Server Public Key ---------- */
    int slen;
    if (read_all(s, (unsigned char*)&slen, sizeof(int)) < 0) return 1;
    slen = ntohl(slen);
    read_all(s, buf, slen);
    BIGNUM *server_pub = BN_bin2bn(buf, slen, NULL);

    /* ---------- DH Key Generation & Send ---------- */
    DH *dh = DH_get_2048_256();
    DH_generate_key(dh);
    const BIGNUM *pub;
    DH_get0_key(dh, &pub, NULL);

    int len = BN_num_bytes(pub);
    BN_bn2bin(pub, buf);
    int nlen = htonl(len);
    write_all(s, (unsigned char*)&nlen, sizeof(nlen));
    write_all(s, buf, len);

    /* ---------- Compute Shared Key ---------- */
    unsigned char secret[256];
    int secret_len = DH_compute_key(secret, server_pub, dh);
    SHA256(secret, secret_len, key);
    
    DH_free(dh);
    BN_free(server_pub);

    /* ---------- Interactive Chat Loop ---------- */
    unsigned char iv[12], tag[16], ciphertext[BUF], plaintext[BUF];
    int ct_len, outlen, final_len;

    printf("[*] Encrypted channel established. You can start typing.\n");

    while (1) {
        // 1. SEND TO SERVER
        printf("Client > ");
        if (!fgets((char*)plaintext, BUF, stdin)) break;
        plaintext[strcspn((char*)plaintext, "\n")] = 0;

        RAND_bytes(iv, 12); 
        EVP_CIPHER_CTX *e_ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(e_ctx, EVP_aes_256_gcm(), NULL, key, iv);
        EVP_EncryptUpdate(e_ctx, ciphertext, &outlen, plaintext, strlen((char*)plaintext));
        EVP_EncryptFinal_ex(e_ctx, ciphertext + outlen, &final_len);
        EVP_CIPHER_CTX_ctrl(e_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

        write_all(s, iv, 12);
        int nct_len = htonl(outlen + final_len);
        write_all(s, (unsigned char*)&nct_len, sizeof(nct_len));
        write_all(s, ciphertext, outlen + final_len);
        write_all(s, tag, 16);
        EVP_CIPHER_CTX_free(e_ctx);

        if (strcmp((char*)plaintext, "exit") == 0) break;

        // 2. RECEIVE FROM SERVER
        printf("[*] Waiting for server response...\n");
        if (read_all(s, iv, 12) <= 0) break;
        read_all(s, (unsigned char*)&ct_len, sizeof(ct_len));
        ct_len = ntohl(ct_len);
        if(ct_len > BUF) break;
        read_all(s, ciphertext, ct_len);
        read_all(s, tag, 16);

        EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(d_ctx, EVP_aes_256_gcm(), NULL, key, iv);
        EVP_DecryptUpdate(d_ctx, plaintext, &outlen, ciphertext, ct_len);
        EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
        
        if (EVP_DecryptFinal_ex(d_ctx, plaintext + outlen, &final_len) > 0) {
            plaintext[outlen + final_len] = 0;
            printf("\nServer: %s\n", plaintext);
            if (strcmp((char*)plaintext, "exit") == 0) {
                EVP_CIPHER_CTX_free(d_ctx);
                break;
            }
        } else {
            printf("\n[-] Decryption Failed\n");
        }
        EVP_CIPHER_CTX_free(d_ctx);
    }

    printf("[+] Closing connection.\n");
    close(s);
    return 0;
}