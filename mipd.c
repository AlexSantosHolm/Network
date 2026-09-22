#include <stddef.h>
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "mip.h"

/** One learned MIP-address-to-Ethernet-address mapping. */
struct arp_cache_entry {
  uint8_t mip_addr;    /**< MIP address represented by this entry. */
  uint8_t mac_addr[6]; /**< Destination Ethernet MAC address. */
  int ifindex;         /**< Interface used to reach mac_addr. */
  time_t timestamp;    /**< Time when the entry was last learned. */
  int valid;           /**< Non-zero while this cache slot is usable. */
};

/** Number of direct-indexed MIP-ARP cache slots. */
#define ARP_CACHE_SIZE 256
/** Daemon-global MIP-ARP cache, indexed by MIP address. */
static struct arp_cache_entry arp_cache[ARP_CACHE_SIZE];

/** A packet retained until MIP-ARP resolves its destination address. */
struct pending_packet {
  uint8_t dst_mip_addr; /**< MIP destination awaiting resolution. */
  uint8_t src_mip_addr; /**< MIP source address for the eventual packet. */
  char payload[256];    /**< Already padded upper-layer SDU. */
  int payload_len;      /**< Size of payload in bytes. */
  time_t timestamp;     /**< Time when the packet entered the queue. */
  int valid;            /**< Non-zero while this slot contains a packet. */
};

/** Maximum number of packets waiting for MIP-ARP resolution. */
#define PENDING_QUEUE_SIZE 32
/** Maximum active Ethernet interfaces discovered for one daemon. */
#define MAX_INTERFACES 16

/** Daemon-global queue of packets waiting for a MIP-ARP response. */
static struct pending_packet pending_queue[PENDING_QUEUE_SIZE];

/** Ethernet information required to transmit on one local interface. */
struct interface_info {
  char name[IFNAMSIZ]; /**< Kernel interface name, for example B-eth0. */
  uint8_t mac_addr[6]; /**< Local Ethernet MAC address. */
  int ifindex;         /**< Kernel interface index used by AF_PACKET. */
};

/** Discovered active non-loopback Ethernet interfaces. */
static struct interface_info local_interfaces[MAX_INTERFACES];
/** Number of valid entries currently stored in local_interfaces. */
static size_t num_local_interfaces;

/**
 * Encode a four-byte MIP-ARP SDU.
 *
 * is_response is zero for a request and non-zero for a response. mip_addr is
 * the MIP address being queried or advertised. The returned value is in
 * network byte order and contains the response bit and address. No global
 * variables are used and there are no error cases.
 */
static uint32_t make_arp_sdu(int is_response, uint8_t mip_addr) {
  uint32_t val =
      ((uint32_t)(is_response & 1) << 31) | ((uint32_t)mip_addr << 23);
  return htonl(val);
}

/**
 * Decode a four-byte MIP-ARP SDU.
 *
 * data points to four bytes received from a MIP packet. is_response receives
 * the request/response bit and mip_addr receives the encoded MIP address.
 * The function returns nothing, uses no global variables, and assumes all
 * pointers are valid and data contains a complete MIP-ARP SDU.
 */
static void read_arp_sdu(const uint8_t *data, int *is_response,
                         uint8_t *mip_addr) {
  uint32_t val;

  memcpy(&val, data, sizeof(val));
  val = ntohl(val);

  *is_response = (val >> 31) & 1;
  *mip_addr = (val >> 23) & 0xff;
}

/** One upper-layer application connected to the daemon's UNIX socket. */
struct client_info {
  int fd;           /**< Connected UNIX SOCK_SEQPACKET descriptor. */
  uint8_t mip_addr; /**< Local MIP address associated with the client. */
  int active;       /**< Non-zero while the descriptor is connected. */
};

/** Daemon-global table of connected upper-layer clients. */
static struct client_info clients[MAX_EVENTS];
/** Number of currently occupied entries in clients. */
static int num_clients = 0;

/**
 * Send one padded MIP ping SDU, or begin MIP-ARP resolution if necessary.
 *
 * See the full definition below for parameter, return-value, and error
 * details. This declaration is needed by process_pending_packets.
 */
static int send_mip_packet(int raw_sock, uint8_t dst_mip_addr,
                           uint8_t src_mip_addr, const char *payload,
                           int payload_len, int debug);

/**
 * Clear every MIP-ARP cache entry.
 *
 * This function has no parameters or return value. It resets the global
 * arp_cache before the daemon event loop starts. No error is possible.
 */
static void init_arp_cache(void) { memset(arp_cache, 0, sizeof(arp_cache)); }

/**
 * Clear all pending-packet slots.
 *
 * This function has no parameters or return value. It resets the global
 * pending_queue before packet processing begins. No error is possible.
 */
static void init_pending_queue(void) {
  memset(pending_queue, 0, sizeof(pending_queue));
}

/**
 * Store a packet while its destination MIP address is being resolved.
 *
 * dst_mip_addr and src_mip_addr become the packet header addresses. payload
 * points to payload_len already padded bytes copied into the global
 * pending_queue. The function returns nothing and silently drops the packet
 * when the queue is full; callers must ensure payload_len fits the buffer.
 */
static void add_pending_packet(uint8_t dst_mip_addr, uint8_t src_mip_addr,
                               const char *payload, int payload_len) {
  for (int i = 0; i < PENDING_QUEUE_SIZE; i++) {
    if (!pending_queue[i].valid) {
      pending_queue[i].dst_mip_addr = dst_mip_addr;
      pending_queue[i].src_mip_addr = src_mip_addr;
      memcpy(pending_queue[i].payload, payload, payload_len);
      pending_queue[i].payload_len = payload_len;
      pending_queue[i].timestamp = time(NULL);
      pending_queue[i].valid = 1;
      break;
    }
  }
}

/**
 * Retry queued packets after learning a destination's MIP-ARP mapping.
 *
 * raw_sock is the AF_PACKET socket, mip_addr selects queued packets, and
 * debug controls status output. The function reads and updates global
 * pending_queue and uses the ARP/interface state indirectly through
 * send_mip_packet. It returns nothing; unsuccessful retries remain queued.
 */
static void process_pending_packets(int raw_sock, uint8_t mip_addr, int debug) {
  for (int i = 0; i < PENDING_QUEUE_SIZE; i++) {
    if (pending_queue[i].valid && pending_queue[i].dst_mip_addr == mip_addr) {
      // Try to send the packet
      if (send_mip_packet(raw_sock, pending_queue[i].dst_mip_addr,
                          pending_queue[i].src_mip_addr,
                          pending_queue[i].payload,
                          pending_queue[i].payload_len, debug) == 0) {
        // Success, remove from queue
        pending_queue[i].valid = 0;
        if (debug) {
          printf("Sent pending packet to MIP %d\n", mip_addr);
        }
      }
    }
  }
}

/**
 * Insert or refresh one MIP-ARP cache entry.
 *
 * mip_addr is the learned MIP address, mac_addr is its Ethernet MAC address,
 * and ifindex is the local interface on which it was learned. The function
 * updates the global arp_cache and returns nothing. It performs no pointer or
 * interface validation because the packet receiver has already validated them.
 */
static void add_arp_entry(uint8_t mip_addr, const uint8_t mac_addr[ETH_ALEN],
                          int ifindex) {
  int index = mip_addr % ARP_CACHE_SIZE;

  arp_cache[index].mip_addr = mip_addr;
  memcpy(arp_cache[index].mac_addr, mac_addr, ETH_ALEN);
  arp_cache[index].ifindex = ifindex;
  arp_cache[index].timestamp = time(NULL);
  arp_cache[index].valid = 1;
}

/**
 * Look up a non-expired MIP-ARP mapping.
 *
 * mip_addr is the address sought. On success mac_addr receives its MAC and
 * ifindex receives its outgoing interface. The function reads and may expire
 * an entry in the global arp_cache. It returns 1 on a fresh match and 0 for a
 * missing or expired entry; output parameters are untouched on failure.
 */
static int find_arp_entry(uint8_t mip_addr, uint8_t mac_addr[ETH_ALEN],
                          int *ifindex) {
  int index = mip_addr % ARP_CACHE_SIZE;

  if (arp_cache[index].valid && arp_cache[index].mip_addr == mip_addr) {
    if (time(NULL) - arp_cache[index].timestamp < 300) {
      memcpy(mac_addr, arp_cache[index].mac_addr, ETH_ALEN);
      *ifindex = arp_cache[index].ifindex;
      return 1;
    }

    arp_cache[index].valid = 0;
  }

  return 0;
}

/**
 * Print all valid MIP-ARP cache mappings to standard output.
 *
 * The function has no parameters or return value. It reads the global
 * arp_cache and is called only when debug output is requested. No error is
 * reported if the cache is empty.
 */
static void print_arp_cache(void) {
  printf("=== MIP-ARP Cache ===\n");
  for (int i = 0; i < ARP_CACHE_SIZE; i++) {
    if (arp_cache[i].valid) {
      printf("MIP %d -> MAC %02x:%02x:%02x:%02x:%02x:%02x on ifindex %d\n",
             arp_cache[i].mip_addr, arp_cache[i].mac_addr[0],
             arp_cache[i].mac_addr[1], arp_cache[i].mac_addr[2],
             arp_cache[i].mac_addr[3], arp_cache[i].mac_addr[4],
             arp_cache[i].mac_addr[5], arp_cache[i].ifindex);
    }
  }
  printf("==================\n");
}

/**
 * Find a previously discovered interface by kernel index.
 *
 * ifindex is the AF_PACKET interface index to search for. The function reads
 * local_interfaces and num_local_interfaces and returns a pointer to the
 * matching entry, or NULL when it is not one of this daemon's interfaces.
 * The returned pointer remains valid until interface discovery runs again.
 */
static const struct interface_info *find_local_interface(int ifindex) {
  for (size_t i = 0; i < num_local_interfaces; i++) {
    if (local_interfaces[i].ifindex == ifindex) {
      return &local_interfaces[i];
    }
  }

  return NULL;
}

/**
 * Discover active local Ethernet interfaces for raw MIP communication.
 *
 * The function has no input parameters. It replaces the daemon-global
 * local_interfaces table and num_local_interfaces with active, non-loopback
 * AF_PACKET interfaces. It returns 0 on success and -1 when getifaddrs fails,
 * too many interfaces are present, or no suitable interface exists.
 */
static int discover_interfaces(void) {
  struct ifaddrs *ifaddrs;
  struct ifaddrs *ifa;

  if (getifaddrs(&ifaddrs) == -1) {
    perror("getifaddrs");
    return -1;
  }

  num_local_interfaces = 0;

  for (ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
    const struct sockaddr_ll *link_addr;
    struct interface_info *iface;

    if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_PACKET ||
        !(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK)) {
      continue;
    }

    link_addr = (const struct sockaddr_ll *)ifa->ifa_addr;

    if (link_addr->sll_halen != ETH_ALEN ||
        find_local_interface(link_addr->sll_ifindex) != NULL) {
      continue;
    }

    if (num_local_interfaces == MAX_INTERFACES) {
      freeifaddrs(ifaddrs);
      fprintf(stderr, "Too many Ethernet interfaces\n");
      return -1;
    }

    iface = &local_interfaces[num_local_interfaces++];
    memset(iface, 0, sizeof(*iface));

    strncpy(iface->name, ifa->ifa_name, IFNAMSIZ - 1);
    memcpy(iface->mac_addr, link_addr->sll_addr, ETH_ALEN);
    iface->ifindex = link_addr->sll_ifindex;
  }

  freeifaddrs(ifaddrs);

  if (num_local_interfaces == 0) {
    fprintf(stderr, "No active Ethernet interfaces found\n");
    return -1;
  }

  return 0;
}

/**
 * Create the raw Ethernet socket used for MIP frames.
 *
 * The function has no input parameters. It first updates local_interfaces by
 * calling discover_interfaces, then creates an AF_PACKET SOCK_RAW socket for
 * ETH_P_MIP. It returns the open descriptor on success or -1 after reporting
 * an interface-discovery or socket-creation error.
 */
static int create_raw_socket(void) {
  int sd;

  if (discover_interfaces() < 0) {
    return -1;
  }

  sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_MIP));
  if (sd == -1) {
    perror("raw sock, AF_PACKET");
    return -1;
  }

  return sd;
}

/**
 * Broadcast a MIP-ARP request on every active Ethernet interface.
 *
 * raw_sock is the raw Ethernet socket, target_mip_addr is the address being
 * resolved, my_mip_addr is the sender address, and debug enables logging.
 * The function reads local_interfaces and num_local_interfaces, sends a
 * broadcast MIP packet with TTL 1, and returns nothing. Individual sendto
 * failures are printed but do not stop requests on later interfaces.
 */
static void send_arp_request(int raw_sock, uint8_t target_mip_addr,
                             uint8_t my_mip_addr, int debug) {
  struct mip_header mip_hdr;
  uint32_t arp_sdu;

  if (debug) {
    printf("Sending MIP-ARP request for MIP address %d\n", target_mip_addr);
  }

  mip_header_set(&mip_hdr, MIP_BROADCAST, my_mip_addr, 1, 1, MIP_SDU_TYPE_ARP);
  arp_sdu = make_arp_sdu(0, target_mip_addr);

  for (size_t i = 0; i < num_local_interfaces; i++) {
    const struct interface_info *iface = &local_interfaces[i];
    struct ethhdr eth_hdr;
    struct sockaddr_ll addr;
    uint8_t frame[ETH_FRAME_LEN];
    int frame_len = 0;

    memset(eth_hdr.h_dest, 0xff, ETH_ALEN);
    memcpy(eth_hdr.h_source, iface->mac_addr, ETH_ALEN);
    eth_hdr.h_proto = htons(ETH_P_MIP);

    memcpy(frame + frame_len, &eth_hdr, sizeof(eth_hdr));
    frame_len += sizeof(eth_hdr);
    memcpy(frame + frame_len, &mip_hdr, sizeof(mip_hdr));
    frame_len += sizeof(mip_hdr);
    memcpy(frame + frame_len, &arp_sdu, sizeof(arp_sdu));
    frame_len += sizeof(arp_sdu);

    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_MIP);
    addr.sll_ifindex = iface->ifindex;
    memset(addr.sll_addr, 0xff, ETH_ALEN);
    addr.sll_halen = ETH_ALEN;

    if (sendto(raw_sock, frame, frame_len, 0, (struct sockaddr *)&addr,
               sizeof(addr)) < 0) {
      perror("sendto ARP request");
    }
  }
}

/**
 * Send a unicast MIP-ARP response on the interface that received the request.
 *
 * raw_sock is the raw Ethernet socket. iface identifies the outgoing local
 * interface. target_mac and target_mip_addr identify the requester, while
 * my_mip_addr is this host's address. debug enables status output. The
 * function returns nothing and prints, rather than returns, a sendto error.
 */
static void send_arp_response(int raw_sock, const struct interface_info *iface,
                              const uint8_t target_mac[ETH_ALEN],
                              uint8_t target_mip_addr, uint8_t my_mip_addr,
                              int debug) {
  struct ethhdr eth_hdr;
  struct mip_header mip_hdr;
  struct sockaddr_ll addr;
  uint8_t frame[ETH_FRAME_LEN];
  uint32_t arp_sdu;
  int frame_len = 0;

  if (debug) {
    printf("Sending MIP-ARP response to MIP address %d on %s\n",
           target_mip_addr, iface->name);
  }

  memcpy(eth_hdr.h_dest, target_mac, ETH_ALEN);
  memcpy(eth_hdr.h_source, iface->mac_addr, ETH_ALEN);
  eth_hdr.h_proto = htons(ETH_P_MIP);

  mip_header_set(&mip_hdr, target_mip_addr, my_mip_addr, MIP_TTL, 1,
                 MIP_SDU_TYPE_ARP);
  arp_sdu = make_arp_sdu(1, my_mip_addr);

  memcpy(frame + frame_len, &eth_hdr, sizeof(eth_hdr));
  frame_len += sizeof(eth_hdr);
  memcpy(frame + frame_len, &mip_hdr, sizeof(mip_hdr));
  frame_len += sizeof(mip_hdr);
  memcpy(frame + frame_len, &arp_sdu, sizeof(arp_sdu));
  frame_len += sizeof(arp_sdu);

  memset(&addr, 0, sizeof(addr));
  addr.sll_family = AF_PACKET;
  addr.sll_protocol = htons(ETH_P_MIP);
  addr.sll_ifindex = iface->ifindex;
  memcpy(addr.sll_addr, target_mac, ETH_ALEN);
  addr.sll_halen = ETH_ALEN;

  if (sendto(raw_sock, frame, frame_len, 0, (struct sockaddr *)&addr,
             sizeof(addr)) < 0) {
    perror("sendto ARP response");
  }
}

/**
 * Encapsulate and transmit a padded ping SDU in a MIP/Ethernet frame.
 *
 * raw_sock is the AF_PACKET socket. dst_mip_addr and src_mip_addr are the MIP
 * header addresses. payload points to payload_len bytes, which must already
 * be divisible by four. debug enables status output. The function reads the
 * global ARP cache and local interface table; broadcast packets use every
 * local interface. It returns 0 after transmission, -2 when it started
 * MIP-ARP resolution, and -1 for an unaligned SDU, unknown cached interface,
 * or send failure.
 */
static int send_mip_packet(int raw_sock, uint8_t dst_mip_addr,
                           uint8_t src_mip_addr, const char *payload,
                           int payload_len, int debug) {
  struct mip_header mip_hdr;
  uint16_t sdu_words;

  if (payload_len % 4 != 0) {
    if (debug) {
      printf("Refusing unaligned SDU\n");
    }
    return -1;
  }

  sdu_words = payload_len / 4;

  mip_header_set(&mip_hdr, dst_mip_addr, src_mip_addr,
                 dst_mip_addr == MIP_BROADCAST ? 1 : MIP_TTL, sdu_words,
                 MIP_SDU_TYPE_PING);

  if (debug) {
    printf("Sending MIP packet: %d -> %d, payload: %.*s\n", src_mip_addr,
           dst_mip_addr, payload_len, payload);
  }

  if (dst_mip_addr == MIP_BROADCAST) {
    int result = 0;

    for (size_t i = 0; i < num_local_interfaces; i++) {
      const struct interface_info *iface = &local_interfaces[i];
      struct ethhdr eth_hdr;
      struct sockaddr_ll addr;
      uint8_t frame[ETH_FRAME_LEN];
      int frame_len = 0;

      memset(eth_hdr.h_dest, 0xff, ETH_ALEN);
      memcpy(eth_hdr.h_source, iface->mac_addr, ETH_ALEN);
      eth_hdr.h_proto = htons(ETH_P_MIP);

      memcpy(frame + frame_len, &eth_hdr, sizeof(eth_hdr));
      frame_len += sizeof(eth_hdr);
      memcpy(frame + frame_len, &mip_hdr, sizeof(mip_hdr));
      frame_len += sizeof(mip_hdr);
      memcpy(frame + frame_len, payload, payload_len);
      frame_len += payload_len;

      memset(&addr, 0, sizeof(addr));
      addr.sll_family = AF_PACKET;
      addr.sll_protocol = htons(ETH_P_MIP);
      addr.sll_ifindex = iface->ifindex;
      memset(addr.sll_addr, 0xff, ETH_ALEN);
      addr.sll_halen = ETH_ALEN;

      if (sendto(raw_sock, frame, frame_len, 0, (struct sockaddr *)&addr,
                 sizeof(addr)) < 0) {
        perror("sendto broadcast MIP packet");
        result = -1;
      }
    }

    return result;
  }

  uint8_t dst_mac[ETH_ALEN];
  int out_ifindex;
  const struct interface_info *iface;
  struct ethhdr eth_hdr;
  struct sockaddr_ll addr;
  uint8_t frame[ETH_FRAME_LEN];
  int frame_len = 0;

  if (!find_arp_entry(dst_mip_addr, dst_mac, &out_ifindex)) {
    if (debug) {
      printf("No ARP entry for MIP address %d, sending ARP request\n",
             dst_mip_addr);
    }

    send_arp_request(raw_sock, dst_mip_addr, src_mip_addr, debug);
    return -2;
  }

  iface = find_local_interface(out_ifindex);
  if (iface == NULL) {
    fprintf(stderr, "ARP cache references unknown interface\n");
    return -1;
  }

  memcpy(eth_hdr.h_dest, dst_mac, ETH_ALEN);
  memcpy(eth_hdr.h_source, iface->mac_addr, ETH_ALEN);
  eth_hdr.h_proto = htons(ETH_P_MIP);

  memcpy(frame + frame_len, &eth_hdr, sizeof(eth_hdr));
  frame_len += sizeof(eth_hdr);
  memcpy(frame + frame_len, &mip_hdr, sizeof(mip_hdr));
  frame_len += sizeof(mip_hdr);
  memcpy(frame + frame_len, payload, payload_len);
  frame_len += payload_len;

  memset(&addr, 0, sizeof(addr));
  addr.sll_family = AF_PACKET;
  addr.sll_protocol = htons(ETH_P_MIP);
  addr.sll_ifindex = iface->ifindex;
  memcpy(addr.sll_addr, dst_mac, ETH_ALEN);
  addr.sll_halen = ETH_ALEN;

  if (sendto(raw_sock, frame, frame_len, 0, (struct sockaddr *)&addr,
             sizeof(addr)) < 0) {
    perror("sendto MIP packet");
    return -1;
  }

  return 0;
}

/**
 * Receive, validate, and process one Ethernet frame carrying MIP.
 *
 * fd is the readable raw socket, my_mip_addr is this host's MIP address,
 * debug enables logging, and raw_sock is used to send ARP responses or queued
 * packets. The function updates global ARP and client state and may use the
 * pending queue. It returns nothing, silently discarding malformed, outgoing,
 * unrelated-interface, or unknown-type frames.
 */
static void handle_raw_socket(int fd, uint8_t my_mip_addr, int debug,
                              int raw_sock) {
  uint8_t frame[ETH_FRAME_LEN];
  struct ethhdr *eth_hdr;
  struct mip_header *mip_hdr;
  int frame_len;
  struct sockaddr_ll addr;
  socklen_t addr_len = sizeof(addr);
  size_t payload_len;
  uint8_t *payload;
  const struct interface_info *incoming_iface;

  frame_len = recvfrom(fd, frame, sizeof(frame), 0, (struct sockaddr *)&addr,
                       &addr_len);
  if (frame_len <= 0) {
    if (debug) {
      printf("recv error on raw socket\n");
    }
    return;
  }

  if (frame_len < (int)(sizeof(struct ethhdr) + sizeof(struct mip_header))) {
    return;
  }

  if (addr.sll_pkttype == PACKET_OUTGOING) {
    return;
  }

  incoming_iface = find_local_interface(addr.sll_ifindex);
  if (incoming_iface == NULL) {
    return;
  }

  // Parse Ethernet header
  eth_hdr = (struct ethhdr *)frame;

  if (debug) {
    printf("Received frame: src MAC %02x:%02x:%02x:%02x:%02x:%02x, "
           "dst MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2],
           eth_hdr->h_source[3], eth_hdr->h_source[4], eth_hdr->h_source[5],
           eth_hdr->h_dest[0], eth_hdr->h_dest[1], eth_hdr->h_dest[2],
           eth_hdr->h_dest[3], eth_hdr->h_dest[4], eth_hdr->h_dest[5]);
  }

  // Parse MIP header
  mip_hdr = (struct mip_header *)(frame + sizeof(struct ethhdr));
  payload_len = (size_t)mip_sdu_words(mip_hdr) * 4;

  if (frame_len <
      (int)(sizeof(struct ethhdr) + sizeof(struct mip_header) + payload_len)) {
    return;
  }

  payload = frame + sizeof(struct ethhdr) + sizeof(struct mip_header);

  if (debug) {
    printf("MIP header: src=%d, dst=%d, ttl=%d, len=%d, type=%d\n",
           mip_hdr->src_addr, mip_hdr->dst_addr, mip_ttl(mip_hdr),
           mip_sdu_words(mip_hdr), mip_sdu_type(mip_hdr));
  }

  // Add sender to ARP cache (only if not broadcast)
  if (mip_hdr->src_addr != MIP_BROADCAST) {
    add_arp_entry(mip_hdr->src_addr, eth_hdr->h_source,
                  incoming_iface->ifindex);
    if (debug) {
      print_arp_cache();
    }
  }

  // Handle different message types
  switch (mip_sdu_type(mip_hdr)) {
  case MIP_SDU_TYPE_PING:
    if (mip_hdr->dst_addr == my_mip_addr ||
        mip_hdr->dst_addr == MIP_BROADCAST) {
      uint8_t msg[ETH_FRAME_LEN];

      msg[0] = mip_hdr->src_addr;
      memcpy(msg + 1, payload, payload_len);

      if (debug) {
        printf("Forwarding to upper layer: from MIP %d, payload: %.*s\n",
               mip_hdr->src_addr, (int)payload_len, payload);
      }

      for (int i = 0; i < num_clients; i++) {
        if (clients[i].active) {
          write(clients[i].fd, msg, 1 + payload_len);
        }
      }
    }
    break;
  case MIP_SDU_TYPE_ARP: {
    int is_response;
    uint8_t arp_mip_addr;

    if (payload_len != sizeof(uint32_t)) {
      break;
    }

    read_arp_sdu(payload, &is_response, &arp_mip_addr);

    if (!is_response) {
      if (debug) {
        printf("Received MIP_ARP request for MIP address %d\n", arp_mip_addr);
      }

      if (arp_mip_addr == my_mip_addr) {
        send_arp_response(raw_sock, incoming_iface, eth_hdr->h_source,
                          mip_hdr->src_addr, my_mip_addr, debug);
      }
    } else {
      if (debug) {
        printf("Recieved MIP_ARP response from MIP address %d\n", arp_mip_addr);
      }

      if (mip_hdr->dst_addr == my_mip_addr &&
          arp_mip_addr == mip_hdr->src_addr) {
        process_pending_packets(raw_sock, arp_mip_addr, debug);
      }
    }
    break;
  }

  default:
    if (debug) {
      printf("Ignoring unknown MIP SDU type %d\n", mip_sdu_type(mip_hdr));
    }
    break;
  }
}

/**
 * Register an upper-layer UNIX client.
 *
 * fd is the connected client descriptor and mip_addr is the daemon's local
 * MIP address stored with that client. The function updates global clients
 * and num_clients, returns nothing, and silently ignores a new client when
 * MAX_EVENTS clients are already tracked.
 */
static void add_client(int fd, uint8_t mip_addr) {
  if (num_clients < MAX_EVENTS) {
    clients[num_clients].fd = fd;
    clients[num_clients].mip_addr = mip_addr;
    clients[num_clients].active = 1;
    num_clients++;
  }
}

/**
 * Remove a disconnected upper-layer client from the client table.
 *
 * fd identifies the client descriptor to remove. The function updates global
 * clients and num_clients, returns nothing, and does nothing if fd is absent.
 * Closing the descriptor remains the caller's responsibility.
 */
static void remove_client(int fd) {
  for (int i = 0; i < num_clients; i++) {
    if (clients[i].fd == fd) {
      clients[i].active = 0;
      for (int j = i; j < num_clients - 1; j++) {
        clients[j] = clients[j + 1];
      }
      num_clients--;
      break;
    }
  }
}

/**
 * Create, bind, and listen on the daemon's UNIX SOCK_SEQPACKET socket.
 *
 * socket_path is the filesystem pathname used as the upper-layer interface.
 * Any stale socket at that path is unlinked before bind. The function returns
 * a listening descriptor on success or -1 after reporting socket, bind, or
 * listen failure. It does not use daemon-global state.
 */
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

/**
 * Register a descriptor for readable events in an epoll instance.
 *
 * efd is the epoll descriptor, ev is the event structure to initialise, and
 * fd is the descriptor to monitor. The function returns 0 on success or -1
 * after reporting an epoll_ctl error. It does not use global variables.
 */
static int add_to_epoll(int efd, struct epoll_event *ev, int fd) {
  ev->events = EPOLLIN;
  ev->data.fd = fd;

  if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, ev) == -1) {
    perror("epoll_ctl");
    return -1;
  }
  return 0;
}

/**
 * Accept an upper-layer client or handle one message from an existing client.
 *
 * fd is the ready descriptor. unix_sock identifies the listening socket;
 * raw_sock carries remote MIP packets; my_mip_addr is this host's address;
 * debug enables logs; and epollfd manages client registrations. The function
 * updates global clients and may update pending/ARP state through
 * send_mip_packet. It returns nothing. It closes and removes clients on EOF
 * or read failure and reports accept or epoll registration errors.
 */
static void handle_unix_socket(int fd, int unix_sock, int raw_sock,
                               uint8_t my_mip_addr, int debug, int epollfd) {
  char buf[257];
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

    add_client(client_fd, my_mip_addr);

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
      printf("Dest addr: %d, Message: %.*s\n", (uint8_t)buf[0], rc - 1,
             buf + 1);
    }

    // Send via network layer
    uint8_t dest_addr = (uint8_t)buf[0];
    char *message = buf + 1;
    int msg_len = rc - 1;

    // Check if destination is ourselves first
    if (dest_addr == my_mip_addr) {
      if (debug) {
        printf("Destination is local, processing directly\n");
      }

      // Forward directly to other local clients
      char local_msg[257];
      local_msg[0] = my_mip_addr; // Source address
      memcpy(local_msg + 1, message, msg_len);

      for (int i = 0; i < num_clients; i++) {
        if (clients[i].active && clients[i].fd != fd) {
          if (debug) {
            printf("Forwarding locally to client %d\n", clients[i].fd);
          }
          write(clients[i].fd, local_msg, 1 + msg_len);
        }
      }
    } else {
      // Send via network to remote host
      int result = send_mip_packet(raw_sock, dest_addr, my_mip_addr, message,
                                   msg_len, debug);

      if (result == -2) {
        // Waiting for ARP - add to pending queue
        if (debug) {
          printf("Adding packet to pending queue for MIP %d\n", dest_addr);
        }
        add_pending_packet(dest_addr, my_mip_addr, message, msg_len);
      } else if (result != 0) {
        if (debug) {
          printf("Failed to send packet\n");
        }
      }
    }
  }
}

/**
 * Run the daemon's epoll-based network and upper-layer event loop.
 *
 * raw_sock receives Ethernet MIP frames. unix_sock accepts local applications.
 * mip_addr is this daemon's MIP address and debug enables console logs. The
 * function initialises global arp_cache and pending_queue, reads the global
 * interface/client state, and dispatches events until epoll_wait fails. It
 * returns nothing; epoll setup failures terminate the process.
 */
void run_daemon(int raw_sock, int unix_sock, uint8_t mip_addr, int debug) {
  struct epoll_event ev, events[MAX_EVENTS];
  int epollfd, i, nfds;

  if (debug) {
    printf("MIP daemon starting at addr: %d\n", mip_addr);

    for (size_t i = 0; i < num_local_interfaces; i++) {
      const struct interface_info *iface = &local_interfaces[i];

      printf("Interface %s: %02x:%02x:%02x:%02x:%02x:%02x\n", iface->name,
             iface->mac_addr[0], iface->mac_addr[1], iface->mac_addr[2],
             iface->mac_addr[3], iface->mac_addr[4], iface->mac_addr[5]);
    }
  }

  init_arp_cache();
  init_pending_queue();

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
        handle_raw_socket(events[i].data.fd, mip_addr, debug, raw_sock);
      } else {
        handle_unix_socket(events[i].data.fd, unix_sock, raw_sock, mip_addr,
                           debug, epollfd);
      }
    }
  }
  close(epollfd);
}

/**
 * Parse daemon options, create sockets, and start the daemon.
 *
 * argc and argv contain `mipd [-h] [-d] <socket_upper> <MIP_address>`.
 * -d enables debug logging and -h prints usage. The function validates that
 * the MIP address is in 0..254, creates the raw and UNIX sockets, invokes
 * run_daemon, then cleans up descriptors and the socket pathname. It returns
 * EXIT_SUCCESS after normal shutdown and exits with EXIT_FAILURE for invalid
 * input or socket setup errors. It affects no globals directly.
 */
int main(int argc, char *argv[]) {
  int opt, debug = 0;
  int raw_sock, unix_sock;
  char *socket_path;
  char *endptr;
  long parsed_addr;
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
  errno = 0;
  parsed_addr = strtol(argv[optind + 1], &endptr, 10);

  if (errno != 0 || *endptr != '\0' || parsed_addr < 0 ||
      parsed_addr >= MIP_BROADCAST) {
    fprintf(stderr, "MIP address must be between 0 and 254\n");
    exit(EXIT_FAILURE);
  }

  mip_addr = (uint8_t)parsed_addr;

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
