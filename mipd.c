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
#include <sys/ioctl.h>
#include <time.h>

#include "mip.h"

// MIP-ARP cache entry
struct arp_cache_entry {
    uint8_t mip_addr;
    uint8_t mac_addr[6];
    time_t timestamp;
    int valid;
};

// ARP cache
#define ARP_CACHE_SIZE 256
static struct arp_cache_entry arp_cache[ARP_CACHE_SIZE];

// Pending packet structure
struct pending_packet {
    uint8_t dst_mip_addr;
    uint8_t src_mip_addr;
    char payload[256];
    int payload_len;
    time_t timestamp;
    int valid;
};

// Pending packets waiting for ARP resolution
#define PENDING_QUEUE_SIZE 32
static struct pending_packet pending_queue[PENDING_QUEUE_SIZE];

// Network interface info
struct interface_info {
    char name[IFNAMSIZ];
    uint8_t mac_addr[6];
    int ifindex;
};

static struct interface_info local_interface;

// Client tracking for upper layer
struct client_info {
    int fd;
    uint8_t mip_addr;
    int active;
};

static struct client_info clients[MAX_EVENTS];
static int num_clients = 0;

// Initialize ARP cache
static void init_arp_cache(void) {
    memset(arp_cache, 0, sizeof(arp_cache));
}

// Initialize pending queue
static void init_pending_queue(void) {
    memset(pending_queue, 0, sizeof(pending_queue));
}

// Add packet to pending queue
static void add_pending_packet(uint8_t dst_mip_addr, uint8_t src_mip_addr,
                              const char* payload, int payload_len) {
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

// Process pending packets for a specific destination
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

// Add entry to ARP cache
static void add_arp_entry(uint8_t mip_addr, uint8_t mac_addr[6]) {
    int index = mip_addr % ARP_CACHE_SIZE;
    
    arp_cache[index].mip_addr = mip_addr;
    memcpy(arp_cache[index].mac_addr, mac_addr, 6);
    arp_cache[index].timestamp = time(NULL);
    arp_cache[index].valid = 1;
}

// Find MAC address in ARP cache
static int find_arp_entry(uint8_t mip_addr, uint8_t mac_addr[6]) {
    int index = mip_addr % ARP_CACHE_SIZE;
    
    if (arp_cache[index].valid && arp_cache[index].mip_addr == mip_addr) {
        // Check if entry is not too old (300 seconds = 5 minutes)
        if (time(NULL) - arp_cache[index].timestamp < 300) {
            memcpy(mac_addr, arp_cache[index].mac_addr, 6);
            return 1;
        } else {
            arp_cache[index].valid = 0;
        }
    }
    return 0;
}

// Print ARP cache (for debugging)
static void print_arp_cache(void) {
    printf("=== MIP-ARP Cache ===\n");
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (arp_cache[i].valid) {
            printf("MIP %d -> MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
                   arp_cache[i].mip_addr,
                   arp_cache[i].mac_addr[0], arp_cache[i].mac_addr[1],
                   arp_cache[i].mac_addr[2], arp_cache[i].mac_addr[3],
                   arp_cache[i].mac_addr[4], arp_cache[i].mac_addr[5]);
        }
    }
    printf("==================\n");
}

// Get interface information
static int get_interface_info(const char *if_name) {
    struct ifreq ifr;
    int sockfd;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    // Get interface index
    strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        close(sockfd);
        return -1;
    }
    local_interface.ifindex = ifr.ifr_ifindex;

    // Get MAC address
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        close(sockfd);
        return -1;
    }
    memcpy(local_interface.mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    strncpy(local_interface.name, if_name, IFNAMSIZ);

    close(sockfd);
    return 0;
}

// Create and bind raw socket to interface
static int create_raw_socket(const char *if_name) {
    int sd;
    struct sockaddr_ll addr;

    sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_MIP));
    if (sd == -1) {
        perror("raw_socket, AF_PACKET");
        return -1;
    }

    // Get interface info
    if (get_interface_info(if_name) < 0) {
        close(sd);
        return -1;
    }

    // Bind to specific interface
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_MIP);
    addr.sll_ifindex = local_interface.ifindex;

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind raw socket");
        close(sd);
        return -1;
    }

    return sd;
}

// Forward declaration
static int send_mip_packet(int raw_sock, uint8_t dst_mip_addr, uint8_t src_mip_addr,
                          const char* payload, int payload_len, int debug);

// Send MIP-ARP request
static void send_arp_request(int raw_sock, uint8_t target_mip_addr, uint8_t my_mip_addr, int debug) {
    struct ethhdr eth_hdr;
    struct mip_header mip_hdr;
    uint8_t frame[ETH_FRAME_LEN];
    int frame_len = 0;
    struct sockaddr_ll addr;

    if (debug) {
        printf("Sending MIP-ARP request for MIP address %d\n", target_mip_addr);
    }

    // Ethernet header - broadcast
    memset(eth_hdr.h_dest, 0xFF, 6);  // Broadcast
    memcpy(eth_hdr.h_source, local_interface.mac_addr, 6);
    eth_hdr.h_proto = htons(ETH_P_MIP);

    // MIP header for ARP request
    memset(&mip_hdr, 0, sizeof(mip_hdr));
    mip_hdr.dst_addr = 0;  // Broadcast
    mip_hdr.src_addr = my_mip_addr;  // Set our MIP address
    mip_hdr.ttl = MIP_TTL;
    mip_hdr.sdu_len = 1;  // Just the target MIP address
    mip_hdr.msg_type = 1;  // ARP request

    // Build frame
    memcpy(frame, &eth_hdr, sizeof(eth_hdr));
    frame_len += sizeof(eth_hdr);
    memcpy(frame + frame_len, &mip_hdr, sizeof(mip_hdr));
    frame_len += sizeof(mip_hdr);
    frame[frame_len] = target_mip_addr;  // Target MIP address
    frame_len += 1;

    // Send frame
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_MIP);
    addr.sll_ifindex = local_interface.ifindex;
    memset(addr.sll_addr, 0xFF, 6);  // Broadcast
    addr.sll_halen = 6;

    if (sendto(raw_sock, frame, frame_len, 0, 
               (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("sendto ARP request");
    }
}

// Send MIP-ARP response
static void send_arp_response(int raw_sock, uint8_t target_mac[6], 
                             uint8_t target_mip_addr, uint8_t my_mip_addr, int debug) {
    struct ethhdr eth_hdr;
    struct mip_header mip_hdr;
    uint8_t frame[ETH_FRAME_LEN];
    int frame_len = 0;
    struct sockaddr_ll addr;

    if (debug) {
        printf("Sending MIP-ARP response to MIP address %d\n", target_mip_addr);
    }

    // Ethernet header - unicast to requester
    memcpy(eth_hdr.h_dest, target_mac, 6);
    memcpy(eth_hdr.h_source, local_interface.mac_addr, 6);
    eth_hdr.h_proto = htons(ETH_P_MIP);

    // MIP header for ARP response
    memset(&mip_hdr, 0, sizeof(mip_hdr));
    mip_hdr.dst_addr = target_mip_addr;
    mip_hdr.src_addr = my_mip_addr;
    mip_hdr.ttl = MIP_TTL;
    mip_hdr.sdu_len = 0;  // No payload for ARP response
    mip_hdr.msg_type = 2;  // ARP response

    // Build frame
    memcpy(frame, &eth_hdr, sizeof(eth_hdr));
    frame_len += sizeof(eth_hdr);
    memcpy(frame + frame_len, &mip_hdr, sizeof(mip_hdr));
    frame_len += sizeof(mip_hdr);

    // Send frame
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_MIP);
    addr.sll_ifindex = local_interface.ifindex;
    memcpy(addr.sll_addr, target_mac, 6);
    addr.sll_halen = 6;

    if (sendto(raw_sock, frame, frame_len, 0, 
               (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("sendto ARP response");
    }
}

// Send MIP data packet
static int send_mip_packet(int raw_sock, uint8_t dst_mip_addr, uint8_t src_mip_addr,
                          const char* payload, int payload_len, int debug) {
    uint8_t dst_mac[6];
    struct ethhdr eth_hdr;
    struct mip_header mip_hdr;
    uint8_t frame[ETH_FRAME_LEN];
    int frame_len = 0;
    struct sockaddr_ll addr;

    // Special case: if destination is ourselves, use our own MAC
    if (dst_mip_addr == src_mip_addr) {
        memcpy(dst_mac, local_interface.mac_addr, 6);
        if (debug) {
            printf("Sending to self, using local MAC address\n");
        }
    } else {
        // Look up destination MAC address
        if (!find_arp_entry(dst_mip_addr, dst_mac)) {
            if (debug) {
                printf("No ARP entry for MIP address %d, sending ARP request\n", dst_mip_addr);
            }
            send_arp_request(raw_sock, dst_mip_addr, src_mip_addr, debug);
            return -2;  // Cannot send now, need to wait for ARP response
        }
    }

    if (debug) {
        printf("Sending MIP packet: %d -> %d, payload: %.*s\n", 
               src_mip_addr, dst_mip_addr, payload_len, payload);
    }

    // Ethernet header
    memcpy(eth_hdr.h_dest, dst_mac, 6);
    memcpy(eth_hdr.h_source, local_interface.mac_addr, 6);
    eth_hdr.h_proto = htons(ETH_P_MIP);

    // MIP header
    memset(&mip_hdr, 0, sizeof(mip_hdr));
    mip_hdr.dst_addr = dst_mip_addr;
    mip_hdr.src_addr = src_mip_addr;
    mip_hdr.ttl = MIP_TTL;
    mip_hdr.sdu_len = (payload_len > 7) ? 7 : payload_len;  // Max 3 bits
    mip_hdr.msg_type = 0;  // Data packet

    // Build frame
    memcpy(frame, &eth_hdr, sizeof(eth_hdr));
    frame_len += sizeof(eth_hdr);
    memcpy(frame + frame_len, &mip_hdr, sizeof(mip_hdr));
    frame_len += sizeof(mip_hdr);
    memcpy(frame + frame_len, payload, payload_len);
    frame_len += payload_len;

    // Send frame
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_MIP);
    addr.sll_ifindex = local_interface.ifindex;
    memcpy(addr.sll_addr, dst_mac, 6);
    addr.sll_halen = 6;

    if (sendto(raw_sock, frame, frame_len, 0, 
               (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("sendto MIP packet");
        return -1;
    }

    return 0;
}

// Handle incoming raw socket data
static void handle_raw_socket(int fd, uint8_t my_mip_addr, int debug, int raw_sock) {
    uint8_t frame[ETH_FRAME_LEN];
    struct ethhdr *eth_hdr;
    struct mip_header *mip_hdr;
    int frame_len;
    struct sockaddr_ll addr;
    socklen_t addr_len = sizeof(addr);

    frame_len = recvfrom(fd, frame, sizeof(frame), 0, 
                        (struct sockaddr*)&addr, &addr_len);
    if (frame_len <= 0) {
        if (debug) {
            printf("recv error on raw socket\n");
        }
        return;
    }

    // Parse Ethernet header
    eth_hdr = (struct ethhdr*)frame;
    
    if (debug) {
        printf("Received frame: src MAC %02x:%02x:%02x:%02x:%02x:%02x, "
               "dst MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2],
               eth_hdr->h_source[3], eth_hdr->h_source[4], eth_hdr->h_source[5],
               eth_hdr->h_dest[0], eth_hdr->h_dest[1], eth_hdr->h_dest[2],
               eth_hdr->h_dest[3], eth_hdr->h_dest[4], eth_hdr->h_dest[5]);
    }

    // Parse MIP header
    mip_hdr = (struct mip_header*)(frame + sizeof(struct ethhdr));
    
    if (debug) {
        printf("MIP header: src=%d, dst=%d, ttl=%d, len=%d, type=%d\n",
               mip_hdr->src_addr, mip_hdr->dst_addr, mip_hdr->ttl, 
               mip_hdr->sdu_len, mip_hdr->msg_type);
    }

    // Add sender to ARP cache (only if not broadcast)
    if (mip_hdr->src_addr != 0) {
        add_arp_entry(mip_hdr->src_addr, eth_hdr->h_source);
        if (debug) {
            print_arp_cache();
        }
    }

    // Handle different message types
    switch (mip_hdr->msg_type) {
        case 0: // Data packet
            if (mip_hdr->dst_addr == my_mip_addr || mip_hdr->dst_addr == 0) {
                // This packet is for us, forward to upper layer
                char msg[256];
                char *payload = (char*)(frame + sizeof(struct ethhdr) + sizeof(struct mip_header));
                int payload_len = mip_hdr->sdu_len;
                
                msg[0] = mip_hdr->src_addr;
                memcpy(msg + 1, payload, payload_len);
                
                if (debug) {
                    printf("Forwarding to upper layer: from MIP %d, payload: %.*s\n",
                           mip_hdr->src_addr, payload_len, payload);
                }
                
                // Send to all connected clients
                for (int i = 0; i < num_clients; i++) {
                    if (clients[i].active) {
                        write(clients[i].fd, msg, 1 + payload_len);
                    }
                }
            }
            break;
            
        case 1: // ARP request
            if (debug) {
                uint8_t target_addr = frame[sizeof(struct ethhdr) + sizeof(struct mip_header)];
                printf("Received ARP request for MIP address %d\n", target_addr);
            }
            
            // Check if the request is for our MIP address
            if (frame[sizeof(struct ethhdr) + sizeof(struct mip_header)] == my_mip_addr) {
                send_arp_response(fd, eth_hdr->h_source, mip_hdr->src_addr, my_mip_addr, debug);
            }
            break;
            
        case 2: // ARP response
            if (debug) {
                printf("Received ARP response from MIP address %d\n", mip_hdr->src_addr);
            }
            // Entry already added to cache above
            // Now process any pending packets for this address
            process_pending_packets(raw_sock, mip_hdr->src_addr, debug);
            break;
    }
}

// Client management functions
static void add_client(int fd, uint8_t mip_addr) {
    if (num_clients < MAX_EVENTS) {
        clients[num_clients].fd = fd;
        clients[num_clients].mip_addr = mip_addr;
        clients[num_clients].active = 1;
        num_clients++;
    }
}

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

static void handle_unix_socket(int fd, int unix_sock, int raw_sock, 
                              uint8_t my_mip_addr, int debug, int epollfd) {
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
            printf("Dest addr: %d, Message: %s\n", (uint8_t)buf[0], buf + 1);
        }

        // Send via network layer
        uint8_t dest_addr = (uint8_t)buf[0];
        char* message = buf + 1;
        int msg_len = rc - 1;

        // Check if destination is ourselves first
        if (dest_addr == my_mip_addr) {
            if (debug) {
                printf("Destination is local, processing directly\n");
            }
            
            // Forward directly to other local clients
            char local_msg[256];
            local_msg[0] = my_mip_addr;  // Source address
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
            int result = send_mip_packet(raw_sock, dest_addr, my_mip_addr,
                                        message, msg_len, debug);
            
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

void run_daemon(int raw_sock, int unix_sock, uint8_t mip_addr, int debug) {
    struct epoll_event ev, events[MAX_EVENTS];
    int epollfd, i, nfds;

    if (debug) {
        printf("MIP daemon starting at addr: %d\n", mip_addr);
        printf("Local MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               local_interface.mac_addr[0], local_interface.mac_addr[1],
               local_interface.mac_addr[2], local_interface.mac_addr[3],
               local_interface.mac_addr[4], local_interface.mac_addr[5]);
    }

    init_arp_cache();
    init_pending_queue();
    
    // Add our own address to ARP cache
    add_arp_entry(mip_addr, local_interface.mac_addr);
    
    if (debug) {
        printf("Added self to ARP cache\n");
        print_arp_cache();
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
                handle_raw_socket(events[i].data.fd, mip_addr, debug, raw_sock);
            } else {
                handle_unix_socket(events[i].data.fd, unix_sock, raw_sock, 
                                 mip_addr, debug, epollfd);
            }
        }
    }
    close(epollfd);
}

int main(int argc, char *argv[]) {
    int opt, debug = 0;
    int raw_sock, unix_sock;
    char *socket_path;
    char *interface = "eth0";  // Default interface
    uint8_t mip_addr;

    while ((opt = getopt(argc, argv, "hdi:")) != -1) {
        switch (opt) {
        case 'h':
            printf("Usage: %s [-h] [-d] [-i interface] <socket_upper> <MIP_address>\n", argv[0]);
            exit(EXIT_SUCCESS);
        case 'd':
            debug = 1;
            break;
        case 'i':
            interface = optarg;
            break;
        default:
            printf("Usage: %s [-h] [-d] [-i interface] <socket_upper> <MIP_address>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (optind + 2 != argc) {
        printf("Usage: %s [-h] [-d] [-i interface] <socket_upper> <MIP_address>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    socket_path = argv[optind];
    mip_addr = atoi(argv[optind + 1]);

    raw_sock = create_raw_socket(interface);
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