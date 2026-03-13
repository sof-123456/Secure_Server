#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 1114
#define BUF 2048

int main() {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(PORT);
    inet_pton(AF_INET, "10.0.3.2", &a.sin_addr);

    char msg[BUF];

    printf("Client > ");
    fflush(stdout); // <--- Add this line
    fgets(msg, BUF, stdin);
    msg[strcspn(msg, "\n")] = 0; // Remove newline

    // Just send the message. Don't add a manual length header.
    // The tunnel sniffs the WHOLE packet (IP+UDP+Data).
    sendto(s, msg, strlen(msg), 0, (struct sockaddr*)&a, sizeof(a));
     
    printf("Sent: %s len %d\n", msg , strlen(msg));
    fflush(stdout);
    close(s);
    return 0;
}