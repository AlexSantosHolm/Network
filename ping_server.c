#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "mip.h"

/**
 * Connect the ping server to the daemon's UNIX SOCK_SEQPACKET socket.
 *
 * socket_path is the filesystem path supplied to the daemon. The function
 * returns a connected descriptor on success or -1 after reporting a socket or
 * connection failure. It has no global state and closes the descriptor before
 * returning an error.
 */
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

/**
 * Receive ping payloads and reply with matching padded pong payloads.
 *
 * socket_path names the daemon's UNIX socket. Each message is expected to
 * contain a one-byte source MIP address followed by a padded payload. For a
 * payload beginning with `PING:`, the function sends that source address plus
 * `PONG:` and the original message text, padded to a 32-bit boundary. It
 * returns nothing, uses no global variables, exits on connection failure, and
 * stops after EOF or a read/write error.
 */
void run_ping_server(const char *socket_path) {
  int sockfd, rc;
  char buf[257];
  char response[257];

  sockfd = connect_to_daemon(socket_path);
  if (sockfd < 0) {
    exit(EXIT_FAILURE);
  }

  printf("Ping to server started\n");

  while (1) {
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

    printf("Received %s\n", payload);

    // CHECK IF IT'S A PING MESSAGE
    if (strncmp(payload, "PING:", 5) == 0) {

      // CREATE A PONG RESPONSE
      snprintf(response + 1, sizeof(response) - 1, "PONG:%s", payload + 5);
      size_t response_len = strlen(response + 1);
      size_t padded_len = (response_len + 3) & ~(size_t)3;

      response[0] = src_addr;

      memset(response + 1 + response_len, 0, padded_len - response_len);

      rc = write(sockfd, response, 1 + padded_len);

      if (rc < 0) {
        perror("write");
        break;
      }

      printf("Sent: %s\n", response + 1);
    }
  }

  close(sockfd);
}

/**
 * Parse ping-server arguments and start the request/reply loop.
 *
 * argc and argv contain `ping_server [-h] <socket_lower>`. The function
 * prints usage for -h, validates that exactly one socket path remains, and
 * invokes run_ping_server. It returns EXIT_SUCCESS after normal completion
 * and exits with EXIT_FAILURE for invalid arguments. It has no global state.
 */
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
