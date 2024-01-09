#ifndef BASIC_FWD_H
#define BASIC_FWD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <sched.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_hexdump.h>
#include <rte_version.h>
#include <rte_hash_crc.h>

#define USE_LRO 1
#define USE_GRO 0

#define BASELINE_MTU 1500
#define CLIENT_MTU 9000
#define TIMER 1

#define RTE_ETHER_ADDR_PRT_FMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define RTE_ETHER_ADDR_BYTES(mac_addrs) ((mac_addrs)->addr_bytes[0]), \
                                        ((mac_addrs)->addr_bytes[1]), \
                                        ((mac_addrs)->addr_bytes[2]), \
                                        ((mac_addrs)->addr_bytes[3]), \
                                        ((mac_addrs)->addr_bytes[4]), \
                                        ((mac_addrs)->addr_bytes[5])
#define MAX_CPUS 16
#define MAX_DPDK_PORTS 8
#define NUM_MBUFS 2048
#define MBUF_CACHE_SIZE 256
#if USE_LRO
// #define MBUF_DATA_SIZE 9024
// #define MBUF_DATA_SIZE 3072
#define MBUF_DATA_SIZE 1536
#else
#define MBUF_DATA_SIZE 1536
#endif
#define MBUF_SIZE (MBUF_DATA_SIZE + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define RX_PTHRESH 8
#define RX_HTHRESH 8
#define RX_WTHRESH 4

#define TX_PTHRESH 36
#define TX_HTHRESH 0
#define TX_WTHRESH 0

#define MAX_PKT_BURST 64

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT	/* 8192 */ /* 4096 */ /* 2048 */ /* 1024 */ /* 512 */ 256 /* 128 */
#define RTE_TEST_TX_DESC_DEFAULT	/* 8192 */ /* 4096 */ /* 2048 */ /* 1024 */ /* 512 */ 256 /* 128 */

#define INVALID_ARRAY_INDEX UINT16_MAX
#define MAX_IPV4_PKT_LENGTH UINT16_MAX
#define MAX_HASH_BUCKET (MAX_PKT_BURST) /* (MAX_PKT_BURST * 2) */
#define MAX_TCP_HLEN 60

#define ETH_HLEN 14
#define IP_HLEN 20
#define TCP_HLEN 20
#define IP_VERSION_IHL 0x45

/* Header fields representing a TCP/IPv4 flow */
struct flow_key
{
    uint32_t ip[2];
    uint16_t port[2];
} __attribute__((packed));

struct flow
{
    /* If the value is NULL, it means the flow is empty */
    struct flow_key *key;
    /*
     * The index of the first packet in the flow
     */
    uint16_t start_item_idx;

    uint16_t next_flow_idx;
};

struct item
{
    /*
     * The first MBUF segment of the packet
     * If the value is NULL, it means the item is empty
     */
    struct rte_mbuf *firstseg;
    /* The last MBUF segment of the packet */
    struct rte_mbuf *lastseg;
    /* TCP sequence number of the packet */
    uint32_t seq;
    /* the number of merged packets */
    uint16_t nb_merged;
    /*
     * next_pkt_idx is used to chain the packets that
     * are in the same flow but can't be merged together
     * (e.g. caused by packet reordering).
     */
    uint16_t next_pkt_idx;
};

/*
 * TCP/IPv4 reassembly table structure.
 */
struct tbl
{
    /* item array */
    struct item *items;
    /* flow array */
    struct flow *flows;
    /* bucket array */
    uint16_t *buckets;
    /* flow index array */
    uint16_t *indices;
    /* current item number */
    uint16_t item_num;
    /* current flow num */
    uint16_t flow_num;
    /* current bucket num */
    uint16_t bucket_num;
};
/* ------------------------------------------------------------------------- */
struct mbuf_table
{
    uint16_t len; /* length of queued packets */
    struct rte_mbuf *table[MAX_PKT_BURST];
};
/* ------------------------------------------------------------------------- */
struct debug_cnt {
    uint64_t prev_sent_bytes;
    uint64_t sent_bytes;
    uint64_t prev_sent_packets;
    uint64_t sent_packets;
};
/* ------------------------------------------------------------------------- */
enum tcp_option
{
    TCP_OPT_END = 0,
    TCP_OPT_NOP = 1,
    TCP_OPT_MSS = 2,
    TCP_OPT_WSCALE = 3,
    TCP_OPT_SACK_PERMIT = 4,
    TCP_OPT_SACK = 5,
    TCP_OPT_TIMESTAMP = 8
};
/* ------------------------------------------------------------------------- */
#endif