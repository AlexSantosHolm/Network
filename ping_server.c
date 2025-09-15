#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "mip.h"

static int connect_to_daemon(const char *socket_path) {
    struct sockaddr_un addr;
    int sd, rc;

    sd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sd < 0) {
        perror("socket");
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    rc = connect(sd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0) {
        perror("connect");
        close(sd);
        return -1;
    }

    return sd;
}

void run_ping_server(const char *socket_path) {
    int sockfd, rc;
    char buf[256];
    char response[256];

    sockfd = connect_to_daemon(socket_path);
    if (sockfd < 0) {
        exit(EXIT_FAILURE);
    }

    printf("Ping to server started\n");

    while(1) {
        memset(buf, 0, sizeof(buf));
        rc = read(sockfd, buf, sizeof(buf));
        if (rc <= 0) {
            if (rc == 0) {
                printf("Daemon disconnected\n");
            } else {
                perror("read");
            }
            break;
        }

        // MESSAGE FORMAT: 1 BYTE SRC ADDR + PAYLOAD
        uint8_t src_addr = buf[0];
        char *payload = buf + 1;

        printf("Recieved %s\n", payload);

        // CHECK IF IT'S A PING MESSAGE
        if (strncmp(payload, "PING:", 5) == 0) {

            // CREATE A PONG RESPONSE
            snprintf(response + 1, sizeof(response) - 1, "PONG:%s", payload + 5);
            response[0] = src_addr;

            rc = write(sockfd, response, 1 + strlen(response + 1));
            if (rc < 0) {
                perror("write");
                break;
            }

            printf("Sent: %s\n", response + 1);
        }
    }

    close(sockfd);
}


int main(int argc, char *argv[]) {
    int opt;

    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
            case 'h':
                printf("Usage: %s [-h] <socket_lower>\n", argv[0]);
                exit(EXIT_SUCCESS);
            default:
                printf("Usage: %s [-h] <socket_lower>\n", argv[0]);
                exit(EXIT_FAILURE);
        }

    }

    if (optind + 1 != argc) {
        printf("Usage: %s [-h] <socket_lower>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    run_ping_server(argv[optind]);

    return 0;
}