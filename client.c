// same includes and helper functions as server.c

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define PORT 1112
#define BUF 2048

// ---------------- send/recv ----------------
int send_all(int fd, unsigned char *buf, int len){
    int total=0;
    while(total<len){
        int s=send(fd,buf+total,len-total,0);
        if(s<=0) return -1;
        total+=s;
    }
    return total;
}

int recv_all(int fd, unsigned char *buf, int len){
    int total=0;
    while(total<len){
        int r=recv(fd,buf+total,len-total,0);
        if(r<=0) return -1;
        total+=r;
    }
    return total;
}

// ---------------- load keys ----------------
EVP_PKEY* load_key(const char* file,int priv){
    FILE* f=fopen(file,"r");
    if(!f) return NULL;
    EVP_PKEY* k= priv ?
        PEM_read_PrivateKey(f,NULL,NULL,NULL) :
        PEM_read_PUBKEY(f,NULL,NULL,NULL);
    fclose(f);
    return k;
}

// ---------------- x25519 ----------------
EVP_PKEY* gen_x25519(){
    EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_X25519,NULL);
    EVP_PKEY *pkey=NULL;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx,&pkey);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

int derive_secret(EVP_PKEY* priv, EVP_PKEY* peer, unsigned char* out){
    EVP_PKEY_CTX* ctx=EVP_PKEY_CTX_new(priv,NULL);
    size_t len=32;
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx,peer);
    EVP_PKEY_derive(ctx,out,&len);
    EVP_PKEY_CTX_free(ctx);
    return len;
}

// ---------------- aes gcm ----------------
int encrypt_msg(unsigned char* key,unsigned char* pt,int plen,
                unsigned char* iv,unsigned char* ct,unsigned char* tag){
    EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();
    int len,clen;
    RAND_bytes(iv,12);
    EVP_EncryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,key,iv);
    EVP_EncryptUpdate(ctx,ct,&len,pt,plen);
    clen=len;
    EVP_EncryptFinal_ex(ctx,ct+len,&len);
    clen+=len;
    EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_GET_TAG,16,tag);
    EVP_CIPHER_CTX_free(ctx);
    return clen;
}

int decrypt_msg(unsigned char* key,unsigned char* ct,int clen,
                unsigned char* iv,unsigned char* tag,unsigned char* pt){
    EVP_CIPHER_CTX* ctx=EVP_CIPHER_CTX_new();
    int len,plen;
    EVP_DecryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,key,iv);
    EVP_DecryptUpdate(ctx,pt,&len,ct,clen);
    plen=len;
    EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_GCM_SET_TAG,16,tag);
    if(EVP_DecryptFinal_ex(ctx,pt+len,&len)<=0) return -1;
    plen+=len;
    EVP_CIPHER_CTX_free(ctx);
    return plen;
}

int main(){

    EVP_PKEY* client_priv=load_key("client_priv.pem",1);
    EVP_PKEY* server_pub=load_key("server_pub.pem",0);

    int s=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in a={0};
    a.sin_family=AF_INET;
    a.sin_port=htons(PORT);
    inet_pton(AF_INET,"127.0.0.1",&a.sin_addr);
    connect(s,(void*)&a,sizeof(a));

    EVP_PKEY* client_eph=gen_x25519();
    unsigned char client_raw[32];
    size_t l=32;
    EVP_PKEY_get_raw_public_key(client_eph,client_raw,&l);

    send_all(s,client_raw,32);
    printf("DH client key: "  );
for (int i = 0; i < l; i++) {
    printf("%02X ",client_raw[i]);
}
printf("\n");

    unsigned char server_raw[32],sig[64];
    recv_all(s,server_raw,32);
        printf("DH server key: "  );
for (int i = 0; i < 32; i++) {
    printf("%02X ",server_raw[i]);
}
printf("\n");
    recv_all(s,sig,64);

    EVP_PKEY* server_eph=
        EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,NULL,server_raw,32);

    unsigned char transcript[64];
    memcpy(transcript,client_raw,32);
    memcpy(transcript+32,server_raw,32);


    printf("transcrypt");
for (int i = 0; i <  64; i++) {    
    printf("%02X ", transcript[i]);
}
printf("\n");

    unsigned char hash[32];
    SHA256(transcript,64,hash);

    EVP_MD_CTX* v=EVP_MD_CTX_new();
    EVP_DigestVerifyInit(v,NULL,NULL,NULL,server_pub);
    if(EVP_DigestVerify(v,sig,64,hash,32)<=0){
        printf("Server auth failed\n");
        return 1;
    }
    EVP_MD_CTX_free(v);

    unsigned char client_sig[64];
    size_t siglen=64;
    EVP_MD_CTX* m=EVP_MD_CTX_new();
    EVP_DigestSignInit(m,NULL,NULL,NULL,client_priv);
    EVP_DigestSign(m,client_sig,&siglen,hash,32);
    EVP_MD_CTX_free(m);

    send_all(s,client_sig,64);
printf("client_sign \n");

    for (int i = 0; i < 64; i++) {
    printf("%02X ",client_sig[i]);
}
printf("\n");

    unsigned char secret[32],key[32];
    derive_secret(client_eph,server_eph,secret);
    SHA256(secret,32,key);

    printf("Secure channel established\n");

    while(1){
        unsigned char iv[12],tag[16],ct[BUF],pt[BUF];

        printf("Client > ");
        fgets((char*)pt,BUF,stdin);
        int plen=strlen((char*)pt);

        int clen=encrypt_msg(key,pt,plen,iv,ct,tag);

printf("[DEBUG] Encrypted (%d bytes): ", clen);
for (int i = 0; i < clen; i++) {    
    printf("%02X ", ct[i]);
}
printf("\n");
        
        int n=htonl(clen);

        send_all(s,iv,12);
        send_all(s,(unsigned char*)&n,4);
        send_all(s,ct,clen);
        send_all(s,tag,16);

        if(recv_all(s,iv,12)<=0) break;
        recv_all(s,(unsigned char*)&clen,4);
        clen=ntohl(clen);
        recv_all(s,ct,clen);
        recv_all(s,tag,16);

        plen=decrypt_msg(key,ct,clen,iv,tag,pt);
        if(plen<0) break;
        pt[plen]=0;
        printf("Server: %s\n",pt);
    }

    close(s);
    return 0;
}
