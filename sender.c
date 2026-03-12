#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <endian.h>

#define PORT 1114
#define BUF 2048

int send_all(int fd, uint8_t *buf, int len)
{
    int total = 0;

    while(total < len)
    {
        int s = send(fd, buf + total, len - total, 0);
        if(s <= 0) return -1;
        total += s;
    }

    return total;
}

int main()
{
    int s = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(PORT);

    inet_pton(AF_INET, "10.0.3.2", &a.sin_addr); // receiver IP
 //inet_pton(AF_INET, "127.0.0.1", &a.sin_addr); // receiver IP
    connect(s, (void*)&a, sizeof(a));

    uint8_t pt[BUF];

    printf("Client > ");
    fgets((char*)pt, BUF, stdin);



    int plen = strlen((char*)pt);
    
    uint64_t plen64 = htobe64(plen);
    send_all(s, (uint8_t*)&plen64, 8);

     
    send_all(s, pt, plen);

    close(s);

    return 0;
}