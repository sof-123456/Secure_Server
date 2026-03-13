#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/kdf.h> 
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>

#define PORT 1112
#define BUF 2048

// --- Helper Functions ---

int send_all(int fd, uint8_t *buf, int len) {
    int total = 0; 
    while (total < len) {
        int s = send(fd, buf + total, len - total, 0);
        if (s <= 0) return -1; 
        total += s;
    } 
    return total;
}

int recv_all(int fd, uint8_t *buf, int len) {
    int total = 0; 
    while (total < len) {
        int r = recv(fd, buf + total, len - total, 0);
        if (r <= 0) return -1;
        total += r;
    }
    return total;
}

EVP_PKEY* load_key(const char* file, int priv) {
    FILE* f = fopen(file, "r"); 
    if (!f) return NULL;
    EVP_PKEY* k = priv ? PEM_read_PrivateKey(f, NULL, NULL, NULL) : PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f); 
    return k;
}

EVP_PKEY* gen_x25519() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY *pkey = NULL; 
    EVP_PKEY_keygen_init(ctx); 
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx); 
    return pkey;
}

int derive_secret(EVP_PKEY* priv, EVP_PKEY* peer, uint8_t *out) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, NULL); 
    size_t len = 32;
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer);
    EVP_PKEY_derive(ctx, out, &len);
    EVP_PKEY_CTX_free(ctx);
    return (int)len;
}

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

int encrypt_msg_with_seq(uint8_t *key, uint8_t *pt, int plen,
                        uint8_t *fixed_nonce, uint64_t seq_num, 
                        uint8_t *ct, uint8_t *tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len, clen; 
    unsigned char iv[12];
    memcpy(iv, fixed_nonce, 4);
    for (int i = 0; i < 8; i++)   
         iv[4 + i] = (seq_num >> (56 - (i * 8))) & 0xFF;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ct, &len, pt, plen); clen = len;
    EVP_EncryptFinal_ex(ctx, ct + len, &len); clen += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx); 
    return clen;
}

int main() {
    // 1. Initial Key Loading
    EVP_PKEY* client_priv = load_key("client_priv.pem", 1);
    EVP_PKEY* server_pub = load_key("server_pub.pem", 0);
    if (!client_priv || !server_pub) {
        fprintf(stderr, "Error loading PEM keys.\n");
        return 1;
    }
    
    int s_decrypt = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET; 
    a.sin_port = htons(PORT);
    inet_pton(AF_INET, "10.0.2.2", &a.sin_addr); 
    
    if (connect(s_decrypt, (struct sockaddr*)&a, sizeof(a)) < 0) {
        perror("Connect to Decryptor failed");
        return 1;
    }

    // --- Handshake ---
    EVP_PKEY* client_eph = gen_x25519();
    unsigned char client_raw[32]; size_t l = 32;
    EVP_PKEY_get_raw_public_key(client_eph, client_raw, &l);
    send_all(s_decrypt, client_raw, 32);

    unsigned char server_raw[32], server_sig[64];
    recv_all(s_decrypt, server_raw, 32);
    EVP_PKEY* server_eph = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, server_raw, 32);

    unsigned char transcript[64];
    memcpy(transcript, client_raw, 32); 
    memcpy(transcript + 32, server_raw, 32);

    recv_all(s_decrypt, server_sig, 64);

    EVP_MD_CTX* v = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(v, NULL, NULL, NULL, server_pub);
    if (EVP_DigestVerify(v, server_sig, 64, transcript, 64) <= 0) {
        printf("Server Auth Fail\n"); 
        return 1; 
    }
    EVP_MD_CTX_free(v);

    unsigned char client_sig[64];
    size_t siglen = 64;
    EVP_MD_CTX* m = EVP_MD_CTX_new();
    EVP_DigestSignInit(m, NULL, NULL, NULL, client_priv);
    EVP_DigestSign(m, client_sig, &siglen, transcript, 64);
    send_all(s_decrypt, client_sig, 64);
    EVP_MD_CTX_free(m);

    // --- Secure Channel Key Derivation ---
    uint8_t key[32], fixed_nonce[4]; 
    unsigned char secret[32], key_material[36];

    derive_secret(client_eph, server_eph, secret);
    if (derive_modern_hkdf(secret, 32, transcript, 64, key_material, 36) < 0) {
        printf("Key derivation failed\n");
        return 1;
    }
    memcpy(key, key_material, 32); 
    memcpy(fixed_nonce, key_material + 32, 4);

    printf("[Proxy] Handshake successful. Tunneling starting...\n");

    // 2. Setup Raw Sniffing
    int s_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("veth_e"); 
    if (bind(s_raw, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("Raw bind failed");
        return 1;
    }

    uint8_t frame[BUF], ct[BUF + 16], tag[16];
    uint64_t send_seq = 0;

    while (1) {
        int frame_len = recv(s_raw, frame, BUF, 0);
        if (frame_len <= 14) continue; 

        // Filter: IPv4 (0x0800) and UDP (17)
        if (frame[12] == 0x08 && frame[13] == 0x00 && frame[23] == 17) {
            
            uint16_t src_port = (frame[34] << 8) | frame[35];
            uint16_t dst_port = (frame[36] << 8) | frame[37];

            // Anti-Loop: Ignore tunnel control traffic
            if (src_port == PORT || dst_port == PORT) continue;

            int clen = encrypt_msg_with_seq(key, frame, frame_len, fixed_nonce, send_seq, ct, tag);

            uint32_t net_len = htonl(clen);
            uint8_t seq_be[8];
            for (int i = 0; i < 8; i++) seq_be[i] = (send_seq >> (56 - i * 8)) & 0xFF;

            if (send_all(s_decrypt, seq_be, 8) < 0) break;
            if (send_all(s_decrypt, (uint8_t*)&net_len, 4) < 0) break;
            if (send_all(s_decrypt, ct, clen) < 0) break;
            if (send_all(s_decrypt, tag, 16) < 0) break;

            printf("[Proxy] Tunneled Packet #%lu (%d bytes) %d\n", send_seq++, frame_len,ct );
        }
    }

    close(s_raw);
    close(s_decrypt);
    return 0;
}