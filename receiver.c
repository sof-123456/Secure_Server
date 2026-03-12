#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>

#define PORT 1114
#define BUF 2048

int recv_all(int fd, uint8_t *buf, int len)
{
    int total = 0;

    while(total < len)
    {
        int r = recv(fd, buf + total, len - total, 0);
        if(r <= 0) return -1;
        total += r;
    }

    return total;
}

int main()
{
    int s = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(PORT);
    a.sin_addr.s_addr = htonl(INADDR_ANY);

    bind(s, (void*)&a, sizeof(a));
    listen(s, 1);

    printf("Listening on %d...\n", PORT);

    int c = accept(s, NULL, NULL);

    uint64_t plen;

    if(recv_all(c, (uint8_t*)&plen, 8) <= 0)
        return 0;

    plen = be64toh(plen);
    uint8_t pt[BUF];

    if(plen >= BUF)
        return 0;

    if(recv_all(c, pt, plen) <= 0)
        return 0;

    pt[plen] = 0;

    printf("From Client: %s\n", pt);

    close(c);
    close(s);

    return 0;
}