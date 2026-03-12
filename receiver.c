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
        // 2. Receive the WHOLE packet (Length + Data) in one go
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        int received = recvfrom(s, buffer, BUF, 0, (struct sockaddr*)&client_addr, &addr_len);
        
        if (received < 0) {
            perror("recvfrom failed");
            break;
        }

        // 3. Process the packet if it has at least the 8-byte length prefix
        if (received >= 8) {
            uint64_t plen;
            memcpy(&plen, buffer, 8);
            plen = be64toh(plen); // Convert from Big Endian

            // 4. Print the message based on the length received
            if (plen > 0 && plen <= (received - 8)) {
                // Ensure we don't overflow our print buffer
                char msg[BUF] = {0};
                memcpy(msg, buffer + 8, plen);
                printf("From Client: %s\n", msg);
            } else {
                printf("Received malformed packet or empty message.\n");
            }
        }
        
        // Clear buffer for next message
        memset(buffer, 0, BUF);
    }

    close(s);
    return 0;
}