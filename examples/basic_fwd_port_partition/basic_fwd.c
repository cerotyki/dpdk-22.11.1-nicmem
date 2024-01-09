#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* See feature_test_macros(7) */
#endif

#include "basic_fwd.h"

int g_num_core;
struct debug_cnt g_debug_cnt[MAX_DPDK_PORTS];
uint16_t tcp_mss[MAX_DPDK_PORTS];
uint16_t mtu[RTE_MAX_ETHPORTS];

struct mbuf_table rmbufs[MAX_DPDK_PORTS]; /* received packets list */
struct mbuf_table wmbufs[MAX_DPDK_PORTS]; /* to be sent packets list */

static struct rte_eth_dev_info dev_info[RTE_MAX_ETHPORTS];
static const uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static const uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
static uint8_t rss_key[] = {
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
    0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
};
struct rte_ether_addr port_list[RTE_MAX_ETHPORTS];
/* ------------------------------------------------------------------------- */
static const struct rte_eth_rxconf rx_conf = {
    .rx_thresh = {
        .pthresh = RX_PTHRESH,
        .hthresh = RX_HTHRESH,
        .wthresh = RX_WTHRESH,
    },
    .rx_free_thresh = 32,
};
static const struct rte_eth_txconf tx_conf = {
    .tx_thresh = {
        .pthresh = TX_PTHRESH,
        .hthresh = TX_HTHRESH,
        .wthresh = TX_WTHRESH,
    },
    .tx_free_thresh = 0,
    .tx_rs_thresh = 0,
};
static struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_RSS,
        .offloads = (
            RTE_ETH_RX_OFFLOAD_RSS_HASH |
#if USE_LRO
            RTE_ETH_RX_OFFLOAD_TCP_LRO |
#endif
#if DEBUG_FLAG
            RTE_ETH_RX_OFFLOAD_TIMESTAMP |
#endif
            RTE_ETH_RX_OFFLOAD_CHECKSUM
        ),
#if USE_LRO
        .max_lro_pkt_size = MBUF_DATA_SIZE,
#endif
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = (RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_TCP),
        },
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
#if RTE_VERSION >= RTE_VERSION_NUM(18, 5, 0, 0)
        .offloads = (
            RTE_ETH_TX_OFFLOAD_MULTI_SEGS |
            RTE_ETH_TX_OFFLOAD_TCP_TSO |
            RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | 
            RTE_ETH_TX_OFFLOAD_UDP_CKSUM | 
            RTE_ETH_TX_OFFLOAD_TCP_CKSUM
        ),
#endif
    },
};

/* ------------------------------------------------------------------------- */
static volatile bool force_quit;
struct rte_mempool *pktmbuf_pool[MAX_DPDK_PORTS] = {NULL};

#define MAX_IP 8
static int num_ip = MAX_IP;
char *ip_addr[MAX_IP] = {
    "10.1.90.2",
    "10.1.95.2",
    "10.2.90.2",
    "10.2.95.2",
    "10.3.90.2",
    "10.3.95.2",
    "10.4.90.2",
    "10.4.95.2",
};
uint32_t ip_list[MAX_IP];
uint8_t mac_addr[MAX_IP][RTE_ETHER_ADDR_LEN] = {
    {0xb8, 0xce, 0xf6, 0xd2, 0xce, 0x16},
    {0xb8, 0xce, 0xf6, 0xd2, 0xca, 0x4a},
    {0x0c, 0x42, 0xa1, 0xca, 0xe8, 0x6c},
    {0x10, 0x70, 0xfd, 0x86, 0x5c, 0x8a},
    {0x98, 0x03, 0x9b, 0x1e, 0xdc, 0x8c},
    {0xb8, 0xce, 0xf6, 0xd2, 0xca, 0x46},
    {0xe8, 0xeb, 0xd3, 0xa7, 0x32, 0xf3},
    {0x98, 0x03, 0x9b, 0x7f, 0xc4, 0x90},
};

struct tbl g_tbl[MAX_DPDK_PORTS];
/*----------------------------------------------------------------------------*/
/* store the packet into the flow */
static inline void
insert_item(struct tbl *tbl,
            struct rte_mbuf *pkt,
            uint32_t seq,
            struct item *prev_item)
{
    struct item *cur_item = &tbl->items[tbl->item_num];
    /* insert new item with the packet */
    cur_item->firstseg = pkt;
    cur_item->lastseg = rte_pktmbuf_lastseg(pkt);
    cur_item->next_pkt_idx = INVALID_ARRAY_INDEX;
    cur_item->seq = seq;
    cur_item->nb_merged = 1;
    if (prev_item)
    {
        /* chain them together. */
        cur_item->next_pkt_idx = prev_item->next_pkt_idx;
        prev_item->next_pkt_idx = tbl->item_num;
    }
    tbl->item_num++;
}
/*----------------------------------------------------------------------------*/
/* store the flow into the array */
static inline void
insert_flow(struct tbl *tbl,
            struct flow_key *key,
            struct flow *prev_flow)
{
    struct flow *cur_flow = &tbl->flows[tbl->flow_num];
    /* insert new flow */
    cur_flow->next_flow_idx = INVALID_ARRAY_INDEX;
    cur_flow->key = key;
    cur_flow->start_item_idx = tbl->item_num;
    if (prev_flow)
    {
        cur_flow->next_flow_idx = prev_flow->next_flow_idx;
        prev_flow->next_flow_idx = tbl->flow_num;
    }
    tbl->flow_num++;
}
/*----------------------------------------------------------------------------*/
/*
 * Check if two TCP/IPv4 packets are neighbors.
 */
static inline int
check_tcph(struct item *item,
           struct rte_tcp_hdr *tcph,
           uint32_t seq,
           uint16_t tcp_hl,
           uint16_t tcp_dl)
{
    struct rte_mbuf *pkt_orig = item->firstseg;
    uint16_t tcp_dl_orig;
    uint16_t optlen;
    tcp_dl_orig = pkt_orig->pkt_len -
                  (ETH_HLEN + IP_HLEN + pkt_orig->l4_len);

    /* Check if TCP option fields equal */
    if (unlikely(tcp_hl != pkt_orig->l4_len))
        return 0;
    optlen = pkt_orig->l4_len - TCP_HLEN;
    if (optlen && memcmp(tcph + 1,
                         (struct rte_tcp_hdr *)(rte_pktmbuf_mtod(pkt_orig, char *) +
                                                ETH_HLEN + IP_HLEN) +
                             1,
                         optlen))
        return 0;

    /* append or pre-pend the new packet */
    return (seq == (item->seq + tcp_dl_orig)) ? 1 : (((seq + tcp_dl) == item->seq) ? -1 : 0);
}
/*----------------------------------------------------------------------------*/
/*
 * Merge two TCP/IPv4 packets without updating checksums.
 * If cmp is larger than 0, append the new packet to the
 * original packet. Otherwise, pre-pend the new packet to
 * the original packet.
 */
static inline int
merge_packet(struct item *cur_item,
             struct rte_mbuf *firstseg,
             struct rte_mbuf *lastseg,
             int cmp,
             int seq)
{
    struct rte_mbuf *pkt_head, *pkt_tail;
    uint16_t hdr_len;

    if (cmp > 0)
    {
        pkt_head = cur_item->firstseg;
        pkt_tail = firstseg;
    }
    else
    {
        pkt_head = firstseg;
        pkt_tail = cur_item->firstseg;
    }

    /* check if the IPv4 packet length is greater than the max value */
    hdr_len = ETH_HLEN + IP_HLEN + pkt_head->l4_len;
    if (unlikely(pkt_head->pkt_len - ETH_HLEN +
                     pkt_tail->pkt_len - hdr_len >
                 MAX_IPV4_PKT_LENGTH))
        return 0;

    /* remove the packet header for the tail packet */
    rte_pktmbuf_adj(pkt_tail, hdr_len);

    /* chain two packets together */
    if (cmp > 0)
    {
        cur_item->lastseg->next = firstseg;
        cur_item->lastseg = lastseg;
    }
    else
    {
        lastseg->next = cur_item->firstseg;
        cur_item->firstseg = firstseg;
        /* update seq to the smaller value */
        cur_item->seq = seq;
    }
    cur_item->nb_merged++;

    /* update MBUF metadata for the merged packet */
    pkt_head->nb_segs += pkt_tail->nb_segs;
    pkt_head->pkt_len += pkt_tail->pkt_len;

    return 1;
}
/*----------------------------------------------------------------------------*/
/*
 * Try assemble this packet to one of existing flows and items
 * Returns -1, if this packet is (unlikely) not supported format,
 * so cannot be assembled; we dont handle this packet as an item
 * Otherwise, returns the number of reduced packets after assemble
 */
static int
assemble_packet(struct tbl *tbl, struct rte_mbuf *pkt)
{
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    struct flow_key *key;
    struct item *cur_item, *prev_item, *merged_item;
    struct flow *cur_flow;
    uint16_t bucket_idx, start_flow_idx;
    uint32_t seq, tcp_hl, tcp_dl;
    int cmp;

    eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    /* not IP */
    if (unlikely(eth_hdr->ether_type != ntohs(RTE_ETHER_TYPE_IPV4)))
        return -1;
    ipv4_hdr = (struct rte_ipv4_hdr *)((char *)eth_hdr + ETH_HLEN);
    /* not TCP */
    if (unlikely(ipv4_hdr->next_proto_id != IPPROTO_TCP))
        return -1;
    /* if IP option exists */
    if (unlikely(ipv4_hdr->version_ihl != IP_VERSION_IHL))
        return -1;
    tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + IP_HLEN);
    /* only process ACK packet (no FIN, SYN, RST, PSH, URG, ECE or CWR set) */
    if (unlikely(tcp_hdr->tcp_flags != RTE_TCP_ACK_FLAG))
        return -1;
    tcp_hl = pkt->l4_len = tcp_hdr->data_off >> 2;
    /* TCP header length out of range */
    if (unlikely((tcp_hl < TCP_HLEN) || (tcp_hl > MAX_TCP_HLEN)))
        return -1;
    tcp_dl = pkt->pkt_len - (ETH_HLEN + IP_HLEN + tcp_hl);
    /* only payload length > 0 */
    if (unlikely(tcp_dl <= 0))
        return -1;
    seq = ntohl(tcp_hdr->sent_seq);
    key = (struct flow_key *)&ipv4_hdr->src_addr;
    // bucket_idx = rte_hash_crc(key, sizeof(struct flow_key), 0) % MAX_HASH_BUCKET;
    bucket_idx = pkt->hash.rss % MAX_HASH_BUCKET;
    start_flow_idx = tbl->buckets[bucket_idx];
    if (start_flow_idx == INVALID_ARRAY_INDEX)
    {
        /* nothing in the bucket; allocate new bucket */
        /* store index to index array in order to simplify flush */
        tbl->indices[tbl->bucket_num] = bucket_idx;
        tbl->buckets[bucket_idx] = tbl->flow_num;
        tbl->bucket_num++;
        insert_flow(tbl, key, NULL);
        insert_item(tbl, pkt, seq, NULL);
        return 0;
    }

    /* find flow for the input pkt */
    cur_flow = &tbl->flows[start_flow_idx];
    while (memcmp(cur_flow->key, key, sizeof(struct flow_key)))
    {
        /* this flow is not for input pkt; collision */
        if (cur_flow->next_flow_idx == INVALID_ARRAY_INDEX)
        {
            /* end of flow list; no flow matched */
            insert_flow(tbl, key, cur_flow);
            insert_item(tbl, pkt, seq, NULL);
            return 0;
        }
        cur_flow = &tbl->flows[cur_flow->next_flow_idx];
    }

    /* find neighbor item for the input pkt */
    prev_item = cur_item = &tbl->items[cur_flow->start_item_idx];
    while (!(cmp = check_tcph(cur_item, tcp_hdr, seq, tcp_hl, tcp_dl)))
    {
        /* this item is not neighbor of input pkt */
        if (cur_item->next_pkt_idx == INVALID_ARRAY_INDEX)
        {
            /* end of item list; no neighbor items matched */
            insert_item(tbl, pkt, seq, cur_item);
            return 0;
        }
        prev_item = cur_item;
        cur_item = &tbl->items[cur_item->next_pkt_idx];
    }

    /* found neighbor item */
    if (!merge_packet(cur_item, pkt, rte_pktmbuf_lastseg(pkt), cmp, seq))
    {
        /* bigger than 64KB; store this packet as a new item */
        insert_item(tbl, pkt, seq, prev_item);
        return 0;
    }

    /* now pkt is merged to one item; we dont need to insert new item */
    /* to solve C -> A -> B issue, check if another item can be merged */
    merged_item = cur_item;
    do
    {
        /* this item is not neighbor of input pkt */
        if (cur_item->next_pkt_idx == INVALID_ARRAY_INDEX)
        {
            /* end of item list; no neighbor items matched */
            return 1;
        }
        prev_item = cur_item;
        cur_item = &tbl->items[cur_item->next_pkt_idx];
    } while (!(cmp = check_tcph(cur_item, tcp_hdr, merged_item->seq, tcp_hl, tcp_dl)));

    /* found second neighbor item */
    if (!merge_packet(cur_item, merged_item->firstseg,
                      merged_item->lastseg, cmp, merged_item->seq))
    {
        /* bigger than 64KB; cannot merge*/
        return 1;
    }

    /* merged again; remove current item because it is merged to prior item */
    prev_item->next_pkt_idx = cur_item->next_pkt_idx;

    return 2;
}
/*----------------------------------------------------------------------------*/
static inline uint16_t
flush_packet(struct tbl *tbl, struct rte_mbuf **out)
{
    struct rte_mbuf *pkt;
    uint16_t cnt = 0, bucket_idx, flow_idx, item_idx, bucket_num = tbl->bucket_num;
    while (tbl->bucket_num > 0)
    {
        bucket_idx = tbl->indices[bucket_num - tbl->bucket_num];
        flow_idx = tbl->buckets[bucket_idx];
        while (flow_idx != INVALID_ARRAY_INDEX)
        {
            item_idx = tbl->flows[flow_idx].start_item_idx;
            while (item_idx != INVALID_ARRAY_INDEX)
            {
                out[cnt++] = tbl->items[item_idx].firstseg;
                if (tbl->items[item_idx].nb_merged > 1)
                {
                    /* update total_length in ip header */
                    pkt = (tbl->items[item_idx]).firstseg;
                    ((struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(pkt, char *) +
                                             ETH_HLEN))
                        ->total_length = htons(pkt->pkt_len - ETH_HLEN);
                }
                /* remove the merged packet from the array */
                item_idx = tbl->items[item_idx].next_pkt_idx;
            }
            /* remove this flow from the array */
            flow_idx = tbl->flows[flow_idx].next_flow_idx;
        }
        tbl->bucket_num--;
        tbl->buckets[bucket_idx] = INVALID_ARRAY_INDEX;
    }

    return cnt;
}
/*----------------------------------------------------------------------------*/
static inline uint16_t
hash_gro(uint16_t portid, struct rte_mbuf **pkts, uint16_t nb_pkts)
{
    struct rte_mbuf *unprocess_pkts[nb_pkts];
    int ret;
    uint16_t i, unprocess_num = 0, nb_after_sort = nb_pkts;
    struct tbl *l_tbl = &g_tbl[portid];

    assert(l_tbl->bucket_num == 0);
    l_tbl->flow_num = l_tbl->item_num = 0;

    for (i = 0; i < nb_pkts; i++)
    {
        ret = assemble_packet(l_tbl, pkts[i]);
        if (ret > 0)
            /* merge successfully */
            nb_after_sort -= ret;
        else if (ret < 0)
            unprocess_pkts[unprocess_num++] = pkts[i];
    }

    if ((nb_after_sort < nb_pkts) || (unprocess_num < nb_pkts))
    {
        /* Flush all packets from the tables */
        i = flush_packet(l_tbl, pkts);
        /* Copy unprocessed packets */
        if (unprocess_num > 0)
            memcpy(&pkts[i], unprocess_pkts,
                   sizeof(struct rte_mbuf *) * unprocess_num);
        nb_after_sort = i + unprocess_num;
    }

    return nb_after_sort;
}
/*----------------------------------------------------------------------------*/
static inline int
table_init(uint16_t portid)
{
    struct tbl *l_tbl = &g_tbl[portid];

    if (!(l_tbl->items = (struct item *)calloc(MAX_PKT_BURST, sizeof(struct item))))
        return -1;
    if (!(l_tbl->flows = (struct flow *)calloc(MAX_PKT_BURST, sizeof(struct flow))))
        return -1;
    if (!(l_tbl->buckets = (uint16_t *)calloc(MAX_HASH_BUCKET, sizeof(uint16_t))))
        return -1;
    for (int i = 0; i < MAX_HASH_BUCKET; i++)
        l_tbl->buckets[i] = INVALID_ARRAY_INDEX;
    if (!(l_tbl->indices = (uint16_t *)calloc(MAX_PKT_BURST, sizeof(uint16_t))))
        return -1;
    l_tbl->item_num = 0;
    l_tbl->flow_num = 0;
    l_tbl->bucket_num = 0;

    return 0;
}
/*----------------------------------------------------------------------------*/
static inline void
table_free(uint16_t portid)
{
    struct tbl *l_tbl = &g_tbl[portid];
    free(l_tbl->items);
    free(l_tbl->flows);
    free(l_tbl->buckets);
    free(l_tbl->indices);
}
/* ------------------------------------------------------------------------- */
static inline void
modify_tcp_mss(uint8_t *tcpopt, int len, uint16_t tcp_mss)
{
    int i;
    unsigned int opt, optlen;
    uint16_t *mss;

    for (i = 0; i < len;)
    {
        opt = *(tcpopt + i++);

        if (opt == TCP_OPT_END)
        { // end of option field
            break;
        }
        else if (opt == TCP_OPT_NOP)
        { // no option
            continue;
        }
        else
        {

            optlen = *(tcpopt + i++);
            if (i + optlen - 2 > len)
            {
                break;
            }

            if (opt == TCP_OPT_MSS)
            {
                mss = (uint16_t *)(tcpopt + i);
                *mss = htons(tcp_mss);
                i += 2;
            }
            else if (opt == TCP_OPT_WSCALE)
            {
                i++;
            }
            else if (opt == TCP_OPT_SACK_PERMIT)
            {
            }
            else if (opt == TCP_OPT_TIMESTAMP)
            {
                i += 8;
            }
            else
            {
                // not handle
                i += optlen - 2;
            }
        }
    }
}
/* ------------------------------------------------------------------------- */
static inline int
get_tcp_mss(uint8_t *tcpopt, int len)
{
    int i;
    unsigned int opt, optlen;
    uint16_t mss;

    for (i = 0; i < len;)
    {
        opt = *(tcpopt + i++);

        if (opt == TCP_OPT_END)
        { // end of option field
            break;
        }
        else if (opt == TCP_OPT_NOP)
        { // no option
            continue;
        }
        else
        {

            optlen = *(tcpopt + i++);
            if (i + optlen - 2 > len)
            {
                break;
            }

            if (opt == TCP_OPT_MSS)
            {
                mss = *(uint16_t *)(tcpopt + i);
                i += 2;
            }
            else if (opt == TCP_OPT_WSCALE)
            {
                i++;
            }
            else if (opt == TCP_OPT_SACK_PERMIT)
            {
            }
            else if (opt == TCP_OPT_TIMESTAMP)
            {
                i += 8;
            }
            else
            {
                // not handle
                i += optlen - 2;
            }
        }
    }

    return ntohs(mss);
}
/* ------------------------------------------------------------------------- */
static inline int
get_dst_mac(uint32_t dip)
{
    int i;

    for (i = 0; i < num_ip; i++)
    {
        if (dip == ip_list[i])
            return i;
    }

    return -1;
}
/* ------------------------------------------------------------------------- */
static inline int
process_pkt(uint16_t port, struct rte_mbuf *m)
{
    struct rte_ether_hdr *ethh = NULL;
    struct rte_ipv4_hdr *iph = NULL;
    struct rte_tcp_hdr *tcph = NULL;
    struct rte_udp_hdr *udph = NULL;
    uint8_t *pktbuf = NULL;
    uint8_t *payload;
    uint32_t saddr, daddr;
    uint32_t len;
    int mac_id;

    if (!m)
        return -1;

    pktbuf = rte_pktmbuf_mtod(m, uint8_t *);
    if (!pktbuf)
        return -1;

    ethh = (struct rte_ether_hdr *)pktbuf;

    if (ethh->ether_type != ntohs(RTE_ETHER_TYPE_IPV4))
        return -1;

    iph = (struct rte_ipv4_hdr *)(ethh + 1);

    if ((iph->next_proto_id != IPPROTO_TCP) && (iph->next_proto_id != IPPROTO_UDP))
        return -1;

	m->l2_len = sizeof(struct rte_ether_hdr);
	m->l3_len = sizeof(struct rte_ipv4_hdr);
    if (iph->next_proto_id == IPPROTO_TCP) {
        tcph = (struct rte_tcp_hdr *)(iph + 1);
#if !USE_GRO
        /* if use GRO, hash_gro function fills this value */
        m->l4_len = tcph->data_off >> 2;
#endif
		if (m->pkt_len > BASELINE_MTU + RTE_ETHER_HDR_LEN) {
			m->tso_segsz = BASELINE_MTU - (m->l3_len + m->l4_len);
			m->ol_flags |= RTE_MBUF_F_TX_TCP_SEG;
		}
		m->ol_flags |= RTE_MBUF_F_TX_IPV4 |
						RTE_MBUF_F_TX_IP_CKSUM |
						RTE_MBUF_F_TX_TCP_CKSUM;
    }
    else if (iph->next_proto_id == IPPROTO_UDP) {
        udph = (struct rte_udp_hdr *)(iph + 1);
        m->l4_len = sizeof(struct rte_udp_hdr);
		m->ol_flags |= RTE_MBUF_F_TX_IPV4 |
						RTE_MBUF_F_TX_IP_CKSUM |
						RTE_MBUF_F_TX_UDP_CKSUM;
    }
    len = m->pkt_len;

    saddr = iph->src_addr;
    daddr = iph->dst_addr;

    mac_id = get_dst_mac(daddr);

    if (mac_id == -1)
        return -1;

    // uint8_t *s, *d;
    // s = (uint8_t *)&saddr;
    // d = (uint8_t *)&daddr;
    // fprintf(stderr, "%02u.%02u.%02u.%02u -> %02u.%02u.%02u.%02u seq: %u, ack: %u, len: %u\n",
    //     s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3],
    //     ntohl(tcph->sent_seq), ntohl(tcph->recv_ack), len);

    /* update mac addresses */
    rte_ether_addr_copy(&ethh->dst_addr, &ethh->src_addr);
    rte_ether_addr_copy((const struct rte_ether_addr *)mac_addr[mac_id], &ethh->dst_addr);

    // fprintf(stderr, "Forward to " RTE_ETHER_ADDR_PRT_FMT"\n",
    //     RTE_ETHER_ADDR_BYTES(&ethh->d_addr));

    g_debug_cnt[port].sent_bytes += len;
    g_debug_cnt[port].sent_packets++;

    return 0;
}
/*----------------------------------------------------------------------------*/
static inline void
print_xstats(int port_id)
{
    int ret, len, i;

    struct rte_eth_xstat *xstats;
    struct rte_eth_xstat_name *xstats_names;
    static const char *stats_border = "_______";

    printf("PORT STATISTICS:\n================\n");
    len = rte_eth_xstats_get(port_id, NULL, 0);
    if (len < 0)
        rte_exit(EXIT_FAILURE,
                 "rte_eth_xstats_get(%u) failed: %d", port_id,
                 len);

    xstats = calloc(len, sizeof(*xstats));
    if (xstats == NULL)
        rte_exit(EXIT_FAILURE,
                 "Failed to calloc memory for xstats");

    ret = rte_eth_xstats_get(port_id, xstats, len);
    if (ret < 0 || ret > len)
    {
        free(xstats);
        rte_exit(EXIT_FAILURE,
                 "rte_eth_xstats_get(%u) len%i failed: %d",
                 port_id, len, ret);
    }

    xstats_names = calloc(len, sizeof(*xstats_names));
    if (xstats_names == NULL)
    {
        free(xstats);
        rte_exit(EXIT_FAILURE,
                 "Failed to calloc memory for xstats_names");
    }

    ret = rte_eth_xstats_get_names(port_id, xstats_names, len);
    if (ret < 0 || ret > len)
    {
        free(xstats);
        free(xstats_names);
        rte_exit(EXIT_FAILURE,
                 "rte_eth_xstats_get_names(%u) len%i failed: %d",
                 port_id, len, ret);
    }

    for (i = 0; i < len; i++)
    {
        if (xstats[i].value > 0)
            printf("Port %u: %s %s:\t\t%" PRIu64 "\n",
                   port_id, stats_border,
                   xstats_names[i].name,
                   xstats[i].value);
    }
}
/* ------------------------------------------------------------------------- */
static int
main_loop(void)
{
    double time_delayed;
    struct rte_mbuf *m;
    struct rte_mbuf **pkts;
    cpu_set_t cpus;
    int recv_cnt, send_cnt, cnt, coreid = rte_lcore_id();

    /* set CPU affinity */
    CPU_ZERO(&cpus);
    CPU_SET(coreid, &cpus);
    if (rte_thread_set_affinity(&cpus) < 0)
    {
        fprintf(stderr, "Failed to set thread affinity for core %d\n", coreid);
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "Lcore id: %d\n", coreid);

    while (!force_quit)
    {
        /* recv packets */
        recv_cnt = rte_eth_rx_burst(coreid, 0, rmbufs[coreid].table, MAX_PKT_BURST);
#if USE_GRO
        recv_cnt = hash_gro(coreid, rmbufs[coreid].table, recv_cnt);
#endif

        /* update and move packets from rmbuf to wmbuf */
        for (int i = 0; i < recv_cnt; i++)
        {
            m = rmbufs[coreid].table[i];
            if (process_pkt(coreid, m) < 0) {
                rte_pktmbuf_free(m);
                continue;
            }
            /* copy to wmbuf */
            wmbufs[coreid].table[wmbufs[coreid].len++] = m;
        }

        /* send packets */
        if (wmbufs[coreid].len)
        {
            cnt = wmbufs[coreid].len;
            pkts = wmbufs[coreid].table;
            do
            {
                send_cnt = rte_eth_tx_burst(coreid, 0, pkts, cnt);
                pkts += send_cnt;
                cnt -= send_cnt;
            } while (cnt > 0);
            wmbufs[coreid].len = 0;
        }
        // if (recv_cnt > 0)
        //     printf("[port %d] recv_cnt: %d, send_cnt: %d\n", portid, recv_cnt, pkts - wmbufs[coreid].table);
    }

    return 0;
}
/* ------------------------------------------------------------------------- */
static inline void
global_init(void)
{
    int nb_ports, portid;
    struct rte_eth_fc_conf fc_conf;
    char if_name[RTE_ETH_NAME_MAX_LEN];
    char mempool_name[RTE_MEMPOOL_NAMESIZE];

    g_num_core = rte_lcore_count();
    if (g_num_core <= 0)
        rte_exit(EXIT_FAILURE, "g_num_core: %d\n", g_num_core);

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports <= 0)
        rte_exit(EXIT_FAILURE, "No available port!\n");
    fprintf(stdout, "%d ports available\n", nb_ports);

    port_conf.rx_adv_conf.rss_conf.rss_key = (uint8_t *)rss_key;
    port_conf.rx_adv_conf.rss_conf.rss_key_len = sizeof(rss_key);

    RTE_ETH_FOREACH_DEV(portid)
    {
        /* Allocate mbuf_pool for each port */
        sprintf(mempool_name, "mbuf_pool-%d", portid);
        pktmbuf_pool[portid] =
            rte_pktmbuf_pool_create(mempool_name, NUM_MBUFS, MBUF_CACHE_SIZE, 0,
            (RTE_PKTMBUF_HEADROOM + sizeof(struct rte_mbuf) + MBUF_DATA_SIZE),
            rte_socket_id());
        if (!pktmbuf_pool[portid])
            rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

        /* Get MAC address of interfaces */
        if (rte_eth_macaddr_get(portid, &port_list[portid]) < 0)
            rte_exit(EXIT_FAILURE, "Cannot get mac address\n");

        rte_eth_dev_info_get(portid, &dev_info[portid]);
        rte_eth_dev_get_name_by_port(portid, if_name);
        fprintf(stdout, "port id: %d, port name: %s\n", portid, if_name);

        if (dev_info[portid].tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
            fprintf(stdout, "[%s] portid %d, mbuf fast free is available.\n", __func__, portid);

        if (dev_info[portid].tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)
            fprintf(stdout, "[%s] portid %d, MULTI_SEGS is available.\n", __func__, portid);

        if (rte_eth_dev_configure(portid, g_num_core, g_num_core, &port_conf) < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure dev\n");

        /* Setup rx_queue */
        if (rte_eth_rx_queue_setup(portid, 0, nb_rxd,
                                    rte_eth_dev_socket_id(portid),
                                    &rx_conf, pktmbuf_pool[portid]) < 0)
            rte_exit(EXIT_FAILURE,
                        "rte_eth_rx_queue_setup: "
                        "err=%d, port=%u, queueid: %d\n",
                        rte_errno, (unsigned)portid, 0);
        /* Setup tx_queue */
        if (rte_eth_tx_queue_setup(portid, 0, nb_txd,
                                    rte_eth_dev_socket_id(portid),
                                    &tx_conf) < 0)
            rte_exit(EXIT_FAILURE,
                        "rte_eth_tx_queue_setup: "
                        "err=%d, port=%u, queueid: %d\n",
                        rte_errno, (unsigned)portid, 0);

        /* setup MTU as larger */
        if (rte_eth_dev_get_mtu(portid, &mtu[portid]) < 0)
            rte_exit(EXIT_FAILURE, "Failed to get MTU, errno: %d\n", rte_errno);
        fprintf(stdout, "[%s][Port %d] original MTU: %u\n", __func__, portid, mtu[portid]);
        if (rte_eth_dev_set_mtu(portid, CLIENT_MTU) < 0)
            rte_exit(EXIT_FAILURE, "Failed to set MTU, errno: %d\n", rte_errno);
        if (rte_eth_dev_get_mtu(portid, &mtu[portid]) < 0)
            rte_exit(EXIT_FAILURE, "Failed to get MTU, errno: %d\n", rte_errno);
        fprintf(stdout, "[%s][Port %d] changed MTU: %u\n", __func__, portid, mtu[portid]);

        /* Start Ethernet device */
        if (rte_eth_dev_start(portid) < 0)
            rte_exit(EXIT_FAILURE, "Failed to start eth_dev!: errno: %d\n", rte_errno);

        if (rte_eth_promiscuous_enable(portid) < 0)
            rte_exit(EXIT_FAILURE, "Failed to set promiscuous mode!: errno: %d\n", rte_errno);

        memset(&fc_conf, 0, sizeof(fc_conf));
        if (rte_eth_dev_flow_ctrl_get(portid, &fc_conf))
            rte_exit(EXIT_FAILURE, "Failed to get flow control into!: errno: %d\n", rte_errno);

        fc_conf.mode = RTE_ETH_FC_NONE;
        if (rte_eth_dev_flow_ctrl_set(portid, &fc_conf))
            rte_exit(EXIT_FAILURE, "Failed to set flow control into!: errno: %d\n", rte_errno);

#if USE_GRO
        if (table_init(portid))
            rte_exit(EXIT_FAILURE, "Failed to init GRO table!\n");
#endif

        g_debug_cnt[portid].prev_sent_bytes = 0;
        g_debug_cnt[portid].sent_bytes = 0;
        g_debug_cnt[portid].prev_sent_packets = 0;
        g_debug_cnt[portid].sent_packets = 0;
    }
}
/* ------------------------------------------------------------------------- */
static void
global_destroy(void)
{
    int portid;

    RTE_ETH_FOREACH_DEV(portid)
    {
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
#if USE_GRO
        table_free(portid);
#endif
    }
}
/* ------------------------------------------------------------------------- */
static void
signal_handler(int signum)
{
    int portid;

    if (signum == SIGINT || signum == SIGTERM)
    {
        printf("\n\nSignal %d received, preparing to exit...\n",
               signum);
        force_quit = true;
        RTE_ETH_FOREACH_DEV(portid)
        {
            print_xstats(portid);
        }
    }
}
/* ------------------------------------------------------------------------- */
int main(int argc, char **argv)
{
    int ret, coreid;

    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Failed to rte_eal_init()\n");

    argc -= ret;
    argv += ret;

    /* make signal handler */
    force_quit = false;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* initialize ip tables */
    for (int i = 0; i < num_ip; i++)
        ip_list[i] = inet_addr(ip_addr[i]);

    global_init();
    if (rte_eal_mp_remote_launch((lcore_function_t *)main_loop, NULL, CALL_MAIN) < 0)
        rte_exit(EXIT_FAILURE, "Failed to rte_eal_mp_remote_launch()\n");
    RTE_LCORE_FOREACH_WORKER(coreid)
    {
        if (rte_eal_wait_lcore(coreid) < 0)
            break;
    }
    global_destroy();

    return 0;
}