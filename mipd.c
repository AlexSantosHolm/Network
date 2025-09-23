#define _GNU_SOURCE
#include <arpa/inet.h> // Added for htons
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

#include "mip.h"

static int create_raw_socket(void) {
  int sd;

  sd = socket(AF_PACKET, SOCK_RAW,
              htons(ETH_P_MIP)); // Fixed missing closing parenthesis

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
    printf("Received %d bytes on raw socket\n",
           rc); // Fixed typo and added newline
  }
}

static void handle_unix_socket(int fd, int unix_sock, int debug,
                               int epollfd) { // Added epollfd parameter
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
      close(fd);
      if (debug) {
        printf("Client %d disconnected\n", fd);
      }
      return;
    }
    if (debug) {
      printf("Received from client %d: %d bytes\n", fd, rc); // Fixed typo
      printf("Dest addr: %d, Message: %s\n", (uint8_t)buf[0], buf + 1);
    }
  }
}

void run_daemon(int raw_sock, int unix_sock, uint8_t mip_addr, int debug) {
  struct epoll_event ev, events[MAX_EVENTS];
  int epollfd, i, nfds; // Removed unused 'rc' variable

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
        handle_unix_socket(events[i].data.fd, unix_sock, debug,
                           epollfd); // Pass epollfd
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
