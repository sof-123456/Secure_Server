#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <endian.h>

#define PORT 1114
#define BUF 2048

int main()
{
    // 1. Change to SOCK_DGRAM for UDP
    int s = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(PORT);
    inet_pton(AF_INET, "10.0.3.2", &a.sin_addr); // Receiver IP
    //inet_pton(AF_INET, "127.0.0.1", &a.sin_addr); // Receiver IP

    uint8_t pt[BUF];
    printf("Client > ");
    if (fgets((char*)pt, BUF, stdin) == NULL) return 0;

    // Remove the newline character if fgets captures it
    pt[strcspn((char*)pt, "\n")] = 0;

    int plen = strlen((char*)pt);
    uint64_t plen64 = htobe64(plen);

    // 2. Prepare the packet (8 bytes length + the message)
    uint8_t packet[BUF + 8];
    memcpy(packet, &plen64, 8);
    memcpy(packet + 8, pt, plen);

    // 3. Use sendto instead of connect/send
    // In UDP, we don't need connect(), we just shoot the packet
    if (sendto(s, packet, plen + 8, 0, (struct sockaddr*)&a, sizeof(a)) < 0) {
        perror("sendto failed");
    } else {
        printf("Sent %d bytes through the tunnel!\n", plen);
    }

    close(s);
    return 0;
}