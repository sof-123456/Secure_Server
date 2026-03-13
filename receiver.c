#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <endian.h>

#define PORT 1114
#define BUF 2048

int main() {
    // 1. Create UDP socket
    int s = socket(AF_INET, SOCK_DGRAM, 0); 
    
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(PORT);
    a.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr*)&a, sizeof(a)) < 0) {
        perror("Bind failed"); 
        return 1;
    }

    printf("UDP Receiver waiting on port %d...\n", PORT);

    uint8_t buffer[BUF];
    while(1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        int received = recvfrom(s, buffer, BUF - 1, 0, (struct sockaddr*)&client_addr, &addr_len);
        
        if (received > 0) {
            buffer[received] = '\0'; // Null-terminate the string
            printf("From Client: %s\n", buffer);
        }
    }
    close(s);
    return 0;
}