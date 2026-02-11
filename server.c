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
    int s, c; // Socket variables
    struct sockaddr_in a;
    unsigned char buf[BUF];
    unsigned char key[32]; // Shared key variable

    s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    a.sin_family = AF_INET;
    a.sin_port = htons(PORT);
    a.sin_addr.s_addr = INADDR_ANY;
    
    if (bind(s, (void*)&a, sizeof(a)) < 0) { perror("Bind failed"); return 1; }
    listen(s, 1);

    printf("[+] Server listening on port %d...\n", PORT);
    c = accept(s, NULL, NULL);
    printf("[+] Client connected!\n");

    /* ---------- Diffie-Hellman Key Exchange ---------- */
    DH *dh = DH_get_2048_256();
    DH_generate_key(dh);
    const BIGNUM *pub;
    DH_get0_key(dh, &pub, NULL);

    int len = BN_num_bytes(pub);
    BN_bn2bin(pub, buf);
    int nlen = htonl(len);
    write_all(c, (unsigned char*)&nlen, sizeof(nlen));
    write_all(c, buf, len);
    
    int clen;
    if (read_all(c, (unsigned char*)&clen, sizeof(clen)) < 0) return 1;
    clen = ntohl(clen);
    read_all(c, buf, clen);
    BIGNUM *client_pub = BN_bin2bn(buf, clen, NULL);

    unsigned char secret[256];
    int secret_len = DH_compute_key(secret, client_pub, dh);
    SHA256(secret, secret_len, key); // Key is now initialized
    DH_free(dh);
    BN_free(client_pub);

    /* ---------- Interactive Chat Loop ---------- */
    unsigned char iv[12], tag[16], ciphertext[BUF], plaintext[BUF];
    int ct_len, outlen, final_len;

    printf("[*] Encrypted channel established. Waiting for client...\n");

    while (1) {
        // 1. RECEIVE FROM CLIENT
        if (read_all(c, iv, 12) <= 0) break;
        read_all(c, (unsigned char*)&ct_len, sizeof(ct_len));
        ct_len = ntohl(ct_len);
        if(ct_len > BUF) break; // Safety check
        read_all(c, ciphertext, ct_len);
        read_all(c, tag, 16);

        EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(d_ctx, EVP_aes_256_gcm(), NULL, key, iv);
        EVP_DecryptUpdate(d_ctx, plaintext, &outlen, ciphertext, ct_len);
        EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
        
        if (EVP_DecryptFinal_ex(d_ctx, plaintext + outlen, &final_len) > 0) {
            plaintext[outlen + final_len] = 0;
            printf("\nClient: %s\n", plaintext);
            if (strcmp((char*)plaintext, "exit") == 0) {
                EVP_CIPHER_CTX_free(d_ctx);
                break;
            }
        } else {
            printf("\n[-] Decryption Failed\n");
        }
        EVP_CIPHER_CTX_free(d_ctx);

        // 2. SEND TO CLIENT
        printf("Server > ");
        if (!fgets((char*)plaintext, BUF, stdin)) break;
        plaintext[strcspn((char*)plaintext, "\n")] = 0;

        RAND_bytes(iv, 12); 
        EVP_CIPHER_CTX *e_ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(e_ctx, EVP_aes_256_gcm(), NULL, key, iv);
        EVP_EncryptUpdate(e_ctx, ciphertext, &outlen, plaintext, strlen((char*)plaintext));
        EVP_EncryptFinal_ex(e_ctx, ciphertext + outlen, &final_len);
        EVP_CIPHER_CTX_ctrl(e_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

        write_all(c, iv, 12);
        int nct_len = htonl(outlen + final_len);
        write_all(c, (unsigned char*)&nct_len, sizeof(nct_len));
        write_all(c, ciphertext, outlen + final_len);
        write_all(c, tag, 16);
        
        EVP_CIPHER_CTX_free(e_ctx);
        if (strcmp((char*)plaintext, "exit") == 0) break;
    }

    printf("[+] Closing connection.\n");
    close(c); 
    close(s);
    return 0;
}