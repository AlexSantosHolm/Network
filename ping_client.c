#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "mip.h"

static int timeout_flag = 0;

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
  char send_buf[256], recv_buf[256];
  char ping_msg[256];
  struct timeval start, end;
  double response_time;

  sock_fd = connect_to_daemon(socket_path);
  if (sock_fd < 0) {
    exit(EXIT_FAILURE);
  }

  // BUILD PING MESSAGE: DESTINATION ADDRESS + PING:MESSAGE
  snprintf(ping_msg, sizeof(ping_msg), "PING:%s", message);

  // MESSAGE FORMAT: 1 byte dest addr + payload
  send_buf[0] = dest_addr;
  strcpy(send_buf + 1, ping_msg);

  // SET UP TIMEOUT
  signal(SIGALRM, timeout_handler);
  timeout_flag = 0;

  // SEND PING
  gettimeofday(&start, NULL);
  alarm(5);

  rc = write(sock_fd, send_buf, 1 + strlen(ping_msg));
  if (rc < 0) {
    perror("write");
    close(sock_fd);
    exit(EXIT_FAILURE);
  }

  // WAIT FOR RESPONSE
  rc = read(sock_fd, recv_buf, sizeof(recv_buf));
  alarm(0);

  if (timeout_flag) {
    printf("TIMEOUT\n");
    close(sock_fd);
    exit(EXIT_FAILURE);
  }

  if (rc <= 0) {
    perror("read");
    close(sock_fd);
    exit(EXIT_FAILURE);
  }

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

  run_ping_client(argv[optind], argv[optind + 1], atoi(argv[optind + 2]));

  return 0;
}
