#define _GNU_SOURCE
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <getopt.h>

#include "mip.h"

// Structure to keep track of clients
struct client_info {
    int fd;
    uint8_t mip_addr;
    int active;
};

// Array to store client information
static struct client_info clients[MAX_EVENTS];
static int num_clients = 0;

// Add a new client to the tracking array
static void add_client(int fd, uint8_t mip_addr) {
    if (num_clients < MAX_EVENTS) {
        clients[num_clients].fd = fd;
        clients[num_clients].mip_addr = mip_addr;
        clients[num_clients].active = 1;
        num_clients++;
    }
}

// Remove a client from the tracking array
static void remove_client(int fd) {
    for (int i = 0; i < num_clients; i++) {
        if (clients[i].fd == fd) {
            clients[i].active = 0;
            // Shift remaining clients down
            for (int j = i; j < num_clients - 1; j++) {
                clients[j] = clients[j + 1];
            }
            num_clients--;
            break;
        }
    }
}

// Find client socket by MIP address
static int find_client_by_addr(uint8_t mip_addr) {
    for (int i = 0; i < num_clients; i++) {
        if (clients[i].active && clients[i].mip_addr == mip_addr) {
            return clients[i].fd;
        }
    }
    return -1; // Not found
}

static int create_raw_socket(void) {
    int sd;
    sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_MIP));
    if (sd == -1) {
        perror("raw_socket, AF_PACKET");
        return -1;
    }
    return sd;
}

static int create_unix_socket(const char *socket_path) {
    struct sockaddr_un addr;
    int sd, rc;

    sd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sd == -1) {
        perror("Unix_socket, AF_UNIX");
        return -1;
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    unlink(socket_path);

    rc = bind(sd, (const struct sockaddr *)&addr, sizeof(addr));
    if (rc == -1) {
        perror("bind");
        close(sd);
        return -1;
    }

    rc = listen(sd, 5);
    if (rc == -1) {
        perror("listen");
        close(sd);
        return -1;
    }

    return sd;
}

static int add_to_epoll(int efd, struct epoll_event *ev, int fd) {
    ev->events = EPOLLIN;
    ev->data.fd = fd;

    if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, ev) == -1) {
        perror("epoll_ctl");
        return -1;
    }
    return 0;
}

static void handle_raw_socket(int fd, int debug) {
    char buf[1500];
    int rc;

    rc = recv(fd, buf, sizeof(buf), 0);
    if (rc <= 0) {
        if (debug) {
            printf("recv error on raw socket\n");
        }
        return;
    }

    if (debug) {
        printf("Received %d bytes on raw socket\n", rc);
    }
}

static void handle_unix_socket(int fd, int unix_sock, int debug, int epollfd, uint8_t daemon_addr) {
    char buf[256];
    int rc, client_fd;
    struct epoll_event ev;

    if (fd == unix_sock) {
        // NEW CONNECTION
        client_fd = accept(fd, NULL, NULL);
        if (client_fd == -1) {
            perror("accept");
            return;
        }
        
        if (debug) {
            printf("New client connected %d\n", client_fd);
        }

        // For simplicity, assign the daemon's address to all clients
        // In a real implementation, you might want different addresses
        add_client(client_fd, daemon_addr);

        // ADD NEW CLIENT TO EPOLL
        if (add_to_epoll(epollfd, &ev, client_fd) == -1) {
            close(client_fd);
            return;
        }

    } else {
        // DATA FROM EXISTING CLIENT
        rc = read(fd, buf, sizeof(buf));

        if (rc <= 0) {
            if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL) == -1) {
                perror("epoll_ctl_del");
            }
            remove_client(fd);
            close(fd);
            if (debug) {
                printf("Client %d disconnected\n", fd);
            }
            return;
        }

        if (debug) {
            printf("Received from client %d: %d bytes\n", fd, rc);
            printf("Dest addr: %d, Message: %s\n", (uint8_t)buf[0], buf + 1);
        }

        // MESSAGE FORWARDING LOGIC
        uint8_t dest_addr = (uint8_t)buf[0];
        
        // Find the destination client
        int dest_fd = find_client_by_addr(dest_addr);
        
        if (dest_fd != -1 && dest_fd != fd) {
            // Forward message to destination client
            // Format: [source_addr][message]
            char forward_buf[256];
            
            // Find source address (the fd that sent this message)
            uint8_t src_addr = daemon_addr; // Default fallback
            for (int i = 0; i < num_clients; i++) {
                if (clients[i].fd == fd && clients[i].active) {
                    src_addr = clients[i].mip_addr;
                    break;
                }
            }
            
            forward_buf[0] = src_addr;
            memcpy(forward_buf + 1, buf + 1, rc - 1);
            
            int write_rc = write(dest_fd, forward_buf, rc);
            if (write_rc < 0) {
                perror("write to destination client");
                if (debug) {
                    printf("Failed to forward message to client %d\n", dest_fd);
                }
            } else {
                if (debug) {
                    printf("Forwarded message from client %d to client %d\n", fd, dest_fd);
                }
            }
        } else {
            if (debug) {
                if (dest_fd == -1) {
                    printf("No client found for destination address %d\n", dest_addr);
                } else if (dest_fd == fd) {
                    printf("Client trying to send to itself\n");
                }
            }
        }
    }
}

void run_daemon(int raw_sock, int unix_sock, uint8_t mip_addr, int debug) {
    struct epoll_event ev, events[MAX_EVENTS];
    int epollfd, i, nfds;

    if (debug) {
        printf("MIP daemon starting at addr: %d\n", mip_addr);
    }

    epollfd = epoll_create1(0);
    if (epollfd == -1) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    if (add_to_epoll(epollfd, &ev, raw_sock) == -1) {
        exit(EXIT_FAILURE);
    }

    if (add_to_epoll(epollfd, &ev, unix_sock) == -1) {
        exit(EXIT_FAILURE);
    }

    while (1) {
        nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            perror("epoll_wait");
            break;
        }

        for (i = 0; i < nfds; i++) {
            if (events[i].data.fd == raw_sock) {
                handle_raw_socket(events[i].data.fd, debug);
            } else {
                handle_unix_socket(events[i].data.fd, unix_sock, debug, epollfd, mip_addr);
            }
        }
    }
    close(epollfd);
}

int main(int argc, char *argv[]) {
    int opt, debug = 0;
    int raw_sock, unix_sock;
    char *socket_path;
    uint8_t mip_addr;

    while ((opt = getopt(argc, argv, "hd")) != -1) {
        switch (opt) {
        case 'h':
            printf("Usage: %s [-h] [-d] <socket_upper> <MIP_address>\n", argv[0]);
            exit(EXIT_SUCCESS);
        case 'd':
            debug = 1;
            break;
        default:
            printf("Usage: %s [-h] [-d] <socket_upper> <MIP_address>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (optind + 2 != argc) {
        printf("Usage: %s [-h] [-d] <socket_upper> <MIP_address>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    socket_path = argv[optind];
    mip_addr = atoi(argv[optind + 1]);

    raw_sock = create_raw_socket();
    if (raw_sock == -1) {
        exit(EXIT_FAILURE);
    }

    unix_sock = create_unix_socket(socket_path);
    if (unix_sock == -1) {
        close(raw_sock);
        exit(EXIT_FAILURE);
    }

    run_daemon(raw_sock, unix_sock, mip_addr, debug);

    close(raw_sock);
    close(unix_sock);
    unlink(socket_path);

    return 0;
}