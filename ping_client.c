#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "mip.h"

static volatile sig_atomic_t timeout_flag = 0;

static void timeout_handler(int sig) {
  (void)sig; // Suppress unused parameter warning
  timeout_flag = 1;
}

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

void run_ping_client(const char *socket_path, const char *message,
                     uint8_t dest_addr) {
  int sock_fd, rc;
  char send_buf[257], recv_buf[257];
  char ping_msg[256], expected_reply[256];
  struct timeval start, end;
  double response_time;
  struct sigaction sa;
  size_t ping_len;
  size_t padded_len;

  sock_fd = connect_to_daemon(socket_path);
  if (sock_fd < 0) {
    exit(EXIT_FAILURE);
  }

  // BUILD PING MESSAGE: DESTINATION ADDRESS + PING:MESSAGE
  snprintf(ping_msg, sizeof(ping_msg), "PING:%s", message);
  snprintf(expected_reply, sizeof(expected_reply), "PONG:%s", message);

  ping_len = strlen(ping_msg);
  padded_len = (ping_len + 3) & ~(size_t)3;

  // MESSAGE FORMAT: 1 byte dest addr + payload
  send_buf[0] = dest_addr;
  memcpy(send_buf + 1, ping_msg, ping_len);
  memset(send_buf + 1 + ping_len, 0, padded_len - ping_len);

  // SET UP TIMEOUT
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = timeout_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  if (sigaction(SIGALRM, &sa, NULL) == -1) {
    perror("sigaction");
    close(sock_fd);
    exit(EXIT_FAILURE);
  }

  timeout_flag = 0;

  // SEND PING
  gettimeofday(&start, NULL);
  alarm(1);

  rc = write(sock_fd, send_buf, 1 + padded_len);
  if (rc < 0) {
    perror("write");
    close(sock_fd);
    exit(EXIT_FAILURE);
  }

  // Wait for the matching PONG reply
  for (;;) {
    rc = read(sock_fd, recv_buf, sizeof(recv_buf) - 1);

    if (rc < 0 && errno == EINTR) {
      if (timeout_flag) {
        printf("timeout\n");
        close(sock_fd);
        return;
      }
      continue;
    }

    if (rc <= 0) {
      perror("read");
      close(sock_fd);
      return;
    }

    recv_buf[rc] = '\0';

    if (strcmp(recv_buf + 1, expected_reply) == 0) {
      break;
    }
  }

  alarm(0);

  gettimeofday(&end, NULL);

  // CALCULATE RESPONSE TIME (Fixed calculation)
  response_time = (end.tv_sec - start.tv_sec) * 1000.0;
  response_time += (end.tv_usec - start.tv_usec) / 1000.0;

  // PRINT RESPONSE
  recv_buf[rc] = '\0';
  printf("Response from %d: %s\n", recv_buf[0], recv_buf + 1);
  printf("Response time: %.2f ms\n", response_time);

  close(sock_fd);
}

int main(int argc, char *argv[]) {

  int opt;
  char *endptr;
  long parsed_addr;

  while ((opt = getopt(argc, argv, "h")) != -1) {
    switch (opt) {
    case 'h':
      printf("Usage %s [-h] <socket_lower> <message> <destination_host>\n",
             argv[0]);
      exit(EXIT_SUCCESS);
    default:
      printf("Usage %s [-h] <socket_lower> <message> <destination_host>\n",
             argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  if (optind + 3 != argc) {
    printf("Usage %s [-h] <socket_lower> <message> <destination_host>\n",
           argv[0]);
    exit(EXIT_FAILURE);
  }

  errno = 0;
  parsed_addr = strtol(argv[optind + 2], &endptr, 10);

  if (errno != 0 || *endptr != '\0' || parsed_addr < 0 ||
      parsed_addr > MIP_BROADCAST) {
    fprintf(stderr, "Destination address must be between 0 and 255\n");
    exit(EXIT_FAILURE);
  }

  run_ping_client(argv[optind], argv[optind + 1], (uint8_t)parsed_addr);

  return 0;
}
