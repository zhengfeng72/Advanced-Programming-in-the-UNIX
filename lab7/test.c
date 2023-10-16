#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

int main(){
    char buffer[1024];

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(0x1337);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    int ret_c = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    ssize_t num_bytes = recv(sockfd, buffer, sizeof(buffer), 0);
    buffer[num_bytes] = '\0';

    close(sockfd);
}