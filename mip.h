#ifndef _MIP_H
#define _MIP_H

#include <stdint.h>

/** Ethernet EtherType used to identify MIP packets. */
#define ETH_P_MIP 0x88B5

/** Default MIP time-to-live value for unicast packets. */
#define MIP_TTL 15
/** Reserved MIP address used for broadcast packets. */
#define MIP_BROADCAST 0xff
/** Maximum number of events returned by one epoll_wait call. */
#define MAX_EVENTS 10

#ifndef ETH_FRAME_LEN
/** Maximum Ethernet frame size, including the Ethernet header. */
#define ETH_FRAME_LEN 1518
#endif

/** SDU type value for a MIP-ARP request or response. */
#define MIP_SDU_TYPE_ARP 0x01
/** SDU type value for the assignment ping protocol. */
#define MIP_SDU_TYPE_PING 0x02

/**
 * Four-byte MIP header in network wire format.
 *
 * dst_addr and src_addr are one-byte MIP addresses. ttl_len holds the 4-bit
 * TTL and high 4 bits of the 9-bit SDU length. len_type holds the remaining
 * 5 length bits and the 3-bit SDU type. packed prevents compiler padding.
 */
struct mip_header {
  uint8_t dst_addr; /**< Destination MIP address. */
  uint8_t src_addr; /**< Source MIP address. */
  uint8_t ttl_len;  /**< TTL and high SDU-length bits. */
  uint8_t len_type; /**< Low SDU-length bits and SDU type. */
} __attribute__((packed));

/**
 * Fill a MIP header with network-layer values.
 *
 * h points to the header to initialise. dst and src are MIP addresses. ttl
 * is a 4-bit lifetime, sdu_words is a 9-bit length in 32-bit words, and
 * sdu_type is a 3-bit SDU identifier. All fields in *h are overwritten.
 *
 * Returns nothing and uses no global variables. Values wider than their
 * wire-format fields are masked rather than reported as errors.
 */
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

/**
 * Reconstruct the final two header bytes as a host-order value.
 *
 * h points to a MIP header. Returns a 16-bit value containing TTL, SDU
 * length, and SDU type in their wire-format bit positions. It uses no global
 * variables; h must be non-NULL.
 */
static inline uint16_t mip_packed_tail(const struct mip_header *h) {
  return ((uint16_t)h->ttl_len << 8) | h->len_type;
}

/**
 * Extract the TTL from a MIP header.
 *
 * h points to the header to inspect. Returns the decoded 4-bit TTL. It uses
 * no global variables and assumes h is non-NULL.
 */
static inline uint8_t mip_ttl(const struct mip_header *h) {
  return (mip_packed_tail(h) >> 12) & 0x0f;
}

/**
 * Extract the SDU length from a MIP header.
 *
 * h points to the header to inspect. Returns the decoded 9-bit SDU length in
 * 32-bit words. It uses no global variables and assumes h is non-NULL.
 */
static inline uint16_t mip_sdu_words(const struct mip_header *h) {
  return (mip_packed_tail(h) >> 3) & 0x01ff;
}

/**
 * Extract the SDU type from a MIP header.
 *
 * h points to the header to inspect. Returns the decoded 3-bit SDU type. It
 * uses no global variables and assumes h is non-NULL.
 */
static inline uint8_t mip_sdu_type(const struct mip_header *h) {
  return mip_packed_tail(h) & 0x07;
}

/**
 * Run the daemon event loop.
 *
 * raw_sock is the AF_PACKET socket, unix_sock is the bound upper-layer UNIX
 * socket, mip_addr is this host's MIP address, and debug enables logging.
 * The function initialises and uses daemon-global ARP, pending, client, and
 * interface state. It returns only after an epoll error.
 */
void run_daemon(int raw_sock, int unix_sock, uint8_t mip_addr, int debug);
/** Run the ping server using socket_path as its lower-layer UNIX socket. */
void run_ping_server(const char *socket_path);
/** Send one ping with message to dest_addr through socket_path. */
void run_ping_client(const char *socket_path, const char *message,
                     uint8_t dest_addr);

#endif // _MIP_H
