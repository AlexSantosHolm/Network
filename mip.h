#ifndef _MIP_H
#define _MIP_H

#include <stdint.h>

#define ETH_P_MIP 0x88B5
#define MIP_TTL 7  // Changed from 15 to 7 (max value for 3-bit field)
#define MAX_EVENTS 10
#ifndef ETH_FRAME_LEN
#define ETH_FRAME_LEN 1518
#endif

struct mip_header {
  uint8_t dst_addr : 4;
  uint8_t src_addr : 4;
  uint8_t ttl : 3;
  uint8_t sdu_len : 3;
  uint8_t msg_type : 2;
  uint16_t reserved;
} __attribute__((packed));

// MIP message types
#define MIP_TYPE_DATA 0
#define MIP_TYPE_ARP_REQ 1
#define MIP_TYPE_ARP_RES 2

// FUNCTION PROTOTYPES
void run_daemon(int raw_sock, int unix_sock, uint8_t mip_addr, int debug);
void run_ping_server(const char *socket_path);
void run_ping_client(const char *socket_path, const char *message,
                     uint8_t dest_addr);

#endif // _MIP_H