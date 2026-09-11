#ifndef _MIP_H
#define _MIP_H

#include <stdint.h>

#define ETH_P_MIP 0x88B5

#define MIP_TTL 15
#define MIP_BROADCAST 0xff
#define MAX_EVENTS 10

#ifndef ETH_FRAME_LEN
#define ETH_FRAME_LEN 1518
#endif

#define MIP_SDU_TYPE_ARP 0x01
#define MIP_SDU_TYPE_PING 0x02

struct mip_header {
  uint8_t dst_addr;
  uint8_t src_addr;
  uint8_t ttl_len;
  uint8_t len_type;
} __attribute__((packed));

static inline void mip_header_set(struct mip_header *h, uint8_t dst,
                                  uint8_t src, uint8_t ttl, uint16_t sdu_words,
                                  uint8_t sdu_type) {
  uint16_t packed;

  h->dst_addr = dst;
  h->src_addr = src;

  packed =
      ((ttl & 0x0f) << 12) | ((sdu_words & 0x01ff) << 3) | (sdu_type & 0x07);

  h->ttl_len = packed >> 8;
  h->len_type = packed & 0xff;
}

static inline uint16_t mip_packed_tail(const struct mip_header *h) {
  return ((uint16_t)h->ttl_len << 8) | h->len_type;
}

static inline uint8_t mip_ttl(const struct mip_header *h) {
  return (mip_packed_tail(h) >> 12) & 0x0f;
}

static inline uint16_t mip_sdu_words(const struct mip_header *h) {
  return (mip_packed_tail(h) >> 3) & 0x01ff;
}

static inline uint8_t mip_sdu_type(const struct mip_header *h) {
  return mip_packed_tail(h) & 0x07;
}

// FUNCTION PROTOTYPES
void run_daemon(int raw_sock, int unix_sock, uint8_t mip_addr, int debug);
void run_ping_server(const char *socket_path);
void run_ping_client(const char *socket_path, const char *message,
                     uint8_t dest_addr);

#endif // _MIP_H
