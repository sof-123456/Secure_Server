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
#include <endian.h>

#define PORT 1112
#define BUF 2048

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

int derive_secret(EVP_PKEY* priv, EVP_PKEY* peer, uint8_t* out) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, NULL);
    size_t len = 32;
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer);
    EVP_PKEY_derive(ctx, out, &len);
    EVP_PKEY_CTX_free(ctx);
    return (int)len;
}

int derive_modern_hkdf(const uint8_t *secret, size_t secret_len, const uint8_t *salt, size_t salt_len, uint8_t *out, size_t out_len) {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[5], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    *p++ = OSSL_PARAM_construct_octet_string("key", (void*)secret, secret_len);
    *p++ = OSSL_PARAM_construct_octet_string("salt", (void*)salt, salt_len);
    *p++ = OSSL_PARAM_construct_octet_string("info", "MySecureApp-v1", 14);
    *p = OSSL_PARAM_construct_end();
    int ret = (EVP_KDF_derive(kctx, out, out_len, params) > 0) ? 0 : -1;
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}

int decrypt_msg_with_seq(uint8_t* key, uint8_t* ct, int clen, uint8_t* fixed_nonce, uint64_t seq_num, uint8_t* tag, uint8_t* pt) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len, plen;
    uint8_t iv[12];
    memcpy(iv, fixed_nonce, 4);
    for (int i = 0; i < 8; i++)
        iv[4 + i] = (seq_num >> (56 - (i * 8))) & 0xFF;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, pt, &len, ct, clen);
    plen = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    int res = EVP_DecryptFinal_ex(ctx, pt + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    return (res > 0) ? (plen + len) : -1;
}


int verify_signature(EVP_PKEY* pub_key, unsigned char* signature, size_t sig_len, unsigned char* data, size_t data_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pub_key) <= 0) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    int result = EVP_DigestVerify(ctx, signature, sig_len, data, data_len);
    EVP_MD_CTX_free(ctx);
    return result; 
}


int create_signature(EVP_PKEY* priv_key, unsigned char* sig_out, size_t* sig_len, unsigned char* data, size_t data_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, priv_key) <= 0) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    
    int result = EVP_DigestSign(ctx, sig_out, sig_len, data, data_len);
    EVP_MD_CTX_free(ctx);
    return result; 
}

int main() {
    EVP_PKEY* server_priv = load_key("server_priv.pem", 1);
    EVP_PKEY* client_pub = load_key("client_pub.pem", 0);
    if (!server_priv || !client_pub) { printf("Key error\n"); return 1; }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(PORT);
    a.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr*)&a, sizeof(a)) < 0) { perror("Bind failed"); return 1; }
    listen(s, 1);
    printf("Decryptor listening on %d...\n", PORT);

    int c = accept(s, NULL, NULL);
    printf("Proxy connected. Starting Handshake...\n");

    // --- Key Exchange ---
    uint8_t client_raw[32];
    recv_all(c, client_raw, 32);
    printf("1. Received Client Eph Key\n");

    EVP_PKEY* client_eph = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, client_raw, 32);
    EVP_PKEY* server_eph = gen_x25519();
    uint8_t server_raw[32];
    size_t l = 32;
    EVP_PKEY_get_raw_public_key(server_eph, server_raw, &l);
    send_all(c, server_raw, 32);

    uint8_t transcript[64];
    memcpy(transcript, client_raw, 32);
    memcpy(transcript + 32, server_raw, 32);

    // --- Authentication ---
    uint8_t sig[64]; 
    uint8_t client_sig[64];

        size_t siglen = 64;
        if (create_signature(server_priv, sig, &siglen, transcript, 64) <= 0) {
            fprintf(stderr, "Server signing failed\n");
            return 1;
        }
        send_all(c, sig, 64);

        if (recv_all(c, client_sig, 64) < 0) {
            fprintf(stderr, "Failed to receive client signature\n");
            return 1;
        }

        if (verify_signature(client_pub, client_sig, 64, transcript, 64) <= 0) {
            printf("Client Auth Fail\n");
            return 1;
        }
    // --- Derivation ---
    uint8_t secret[32], key[32], fixed_nonce[4], key_material[36];
    derive_secret(server_eph, client_eph, secret);
    derive_modern_hkdf(secret, 32, transcript, 64, key_material, 36);
    memcpy(key, key_material, 32);
    memcpy(fixed_nonce, key_material + 32, 4);
    printf("Secure channel established.\n");

    // --- Packet Injection Setup ---
    int s_inject = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("veth_d2");
    sll.sll_protocol = htons(ETH_P_ALL);

    uint8_t seq_buf[8], tag[16], ct[BUF], pt[BUF];
    uint32_t net_len;

    while (1) {
        // 1. Get Sequence
        if (recv_all(c, seq_buf, 8) <= 0) break;
        uint64_t rseq = 0;
        for (int i = 0; i < 8; i++)
            rseq = (rseq << 8) | seq_buf[i];

        // 2. Get Length
        if (recv_all(c, (uint8_t*)&net_len, 4) <= 0) break;
        int clen = ntohl(net_len);
        if (clen > BUF || clen <= 0) break;

        // 3. Get Data & Tag
        if (recv_all(c, ct, clen) <= 0) break;
        if (recv_all(c, tag, 16) <= 0) break;

        // 4. Decrypt
        int plen = decrypt_msg_with_seq(key, ct, clen, fixed_nonce, rseq, tag, pt);
        if (plen < 0) {
            printf("Integrity Failure on Packet #%lu\n", rseq);
            continue;
        }

        // 5. Inject raw Ethernet frame
        if ( sendto(s_inject, pt, plen, 0, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
            perror("Injection failed");
        } else {
            printf("[Decryptor] Injected Frame #%lu (%d bytes) %s \n", rseq, plen, pt);
        }
        // Calculate where the UDP payload begins
    int header_offset = 14 + 20 + 8; 
    
    if (plen > header_offset) {
    
        printf("[Decryptor] Packet #%lu | Payload: %.*s\n", 
                rseq, (plen - header_offset), pt + header_offset);
    } else {
        printf("[Decryptor] Packet #%lu | (No payload or non-UDP frame)\n", rseq);
    }
    }

    close(c); 
    close(s);
    close(s_inject);
    return 0;
}