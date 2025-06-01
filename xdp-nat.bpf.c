#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef INTERNAL_SUBNET
#define INTERNAL_SUBNET 0x00000000
#endif
#ifndef INTERNAL_MASK
#define INTERNAL_MASK 0x00000000
#endif
#ifndef PUBLIC_IP
#define PUBLIC_IP 0x00000000
#endif

#define NUM_L4_PROTOCOL 3
#define MAX_ENTRIES_PER_L4_PROTOCOL 65536
#define MAX_ENTRIES (MAX_ENTRIES_PER_L4_PROTOCOL * NUM_L4_PROTOCOL)
#define TCP_UDP_MIN_PORT 1024
#define TCP_UDP_MAX_PORT 65535
#define TCP_UDP_RANGE (TCP_UDP_MAX_PORT - TCP_UDP_MIN_PORT + 1)

#define IP_MF 0x2000     // More Fragments flag
#define IP_OFFSET 0x1FFF // Fragment offset mask

struct nat_session_key {
    __u8 protocol;
    __u32 internal_ip;
    __u16 internal_port; // ICMP ID for ICMP instead of port
    __u32 dest_ip;
    __u16 dest_port; // constance 0 for ICMP
};

struct nat_session_value {
    __u16 nat_external_port; // ICMP ID for ICMP 
};

struct port_lookup_key {
    __u8 protocol;
    __u16 dest_port; // translated port
};

struct port_lookup_value {
    __u32 internal_ip;
    __u16 internal_port; // ICMP ID for ICMP 
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct nat_session_key);
    __type(value, struct nat_session_value);
    __uint(max_entries, MAX_ENTRIES);
} nat_sessions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct port_lookup_key);
    __type(value, struct port_lookup_value);
    __uint(max_entries, MAX_ENTRIES);
} port_lookup SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 3); // TCP(0), UDP(1), ICMP(2)
} port_counters SEC(".maps");

#define MAX_CHECKSUM_BYTES 1500
#define MAX_CSUM_WORDS 750
#define MAX_CSUM_BYTES (MAX_CSUM_WORDS * 2)

static __u16 csum_fold_helper(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return ~csum;
}

static __u16 iph_csum(struct iphdr *iph) {
    iph->check = 0;
    __u32 csum =
        bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

static __u32 sum16_32(__u32 v) { return (v >> 16) + (v & 0xffff); }

struct sum16_ctx {
    const __u16 *data;
    __u32 size;
    const void *data_end;
    __u32 sum;
};

static long sum16_callback(__u32 i, struct sum16_ctx *ctx) {
    if (i >= MAX_CSUM_WORDS || 2 * i >= ctx->size)
        return 1;

    const void *ptr = (const void *)ctx->data + (i * 2);

    if (ptr + 2 > ctx->data_end) {
        if (ctx->size % 2 == 0) {
            ctx->sum = 0;
            return 1;
        }

        const __u8 *last_byte = ptr;
        if ((void *)last_byte + 1 > ctx->data_end) {
            ctx->sum = 0;
            return 1;
        }
        ctx->sum += (*last_byte);
        return 1;
    }

    ctx->sum += *(const __u16 *)ptr;
    return 0;
}

static __u32 sum16(const void *data, __u32 size, const void *data_end) {
    struct sum16_ctx ctx = {
        .data = (const __u16 *)data,
        .size = size,
        .data_end = data_end,
        .sum = 0,
    };

    __u32 max_iterations = (size + 1) / 2;
    if (max_iterations > MAX_CSUM_WORDS)
        max_iterations = MAX_CSUM_WORDS;

    bpf_loop(max_iterations, sum16_callback, &ctx, 0);

    return ctx.sum;
}

static __u16 carry(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return ~csum;
}

static void update_ip_checksum(struct iphdr *iph) {
    iph->check = iph_csum(iph);
}

static int update_tcp_checksum(struct iphdr *iph, struct tcphdr *tcph,
                               void *data_end) {
    __u32 tcp_len = bpf_ntohs(iph->tot_len) - (iph->ihl << 2);

    if ((void *)tcph + tcp_len > data_end) {
        bpf_printk("TCP checksum: tcp_end > data_end");
        return -1;
    }

    if (tcp_len > MAX_CHECKSUM_BYTES) {
        bpf_printk("TCP checksum: tcp_len(%d) > MAX_CHECKSUM_BYTES(%d)",
                   tcp_len, MAX_CHECKSUM_BYTES);
        return -1;
    }

    __u32 tcp_csum = 0;
    tcp_csum += sum16_32(iph->saddr);
    tcp_csum += sum16_32(iph->daddr);
    tcp_csum += bpf_htons(IPPROTO_TCP);
    tcp_csum += bpf_htons(tcp_len);
    if ((void *)(tcph + 1) > data_end)
        return -1;
    tcph->check = 0;
    tcp_csum += sum16(tcph, tcp_len, data_end);
    tcph->check = carry(tcp_csum);

    return 0;
}

static int update_udp_checksum(struct iphdr *iph, struct udphdr *udph,
                               void *data_end) {
    __u32 udp_len = bpf_ntohs(udph->len);

    if (udp_len > MAX_CHECKSUM_BYTES) {
        bpf_printk("UDP checksum: udp_len(%d) > MAX_CHECKSUM_BYTES(%d)",
                   udp_len, MAX_CHECKSUM_BYTES);
        return -1;
    }

    if ((void *)udph + udp_len > data_end) {
        bpf_printk("UDP checksum: udp_end > data_end");
        return -1;
    }

    __u32 udp_csum = 0;
    udp_csum += sum16_32(iph->saddr);
    udp_csum += sum16_32(iph->daddr);
    udp_csum += bpf_htons(IPPROTO_UDP);
    udp_csum += bpf_htons(udp_len);
    udph->check = 0;
    udp_csum += sum16(udph, udp_len, data_end);
    udph->check = carry(udp_csum);

    return 0;
}

static int update_icmp_checksum(struct iphdr *iph, struct icmphdr *icmph,
                                void *data_end) {
    __u32 icmp_len = bpf_ntohs(iph->tot_len) - (iph->ihl << 2);

    if ((void *)icmph + icmp_len > data_end) {
        bpf_printk("ICMP checksum: icmp_end > data_end");
        return -1;
    }

    if (icmp_len > MAX_CHECKSUM_BYTES) {
        bpf_printk("ICMP checksum: icmp_len(%d) > MAX_CHECKSUM_BYTES(%d)",
                   icmp_len, MAX_CHECKSUM_BYTES);
        return -1;
    }

    icmph->checksum = 0;
    __u32 icmp_csum = sum16(icmph, icmp_len, data_end);
    icmph->checksum = carry(icmp_csum);

    return 0;
}

static void init_fib_params(struct bpf_fib_lookup *fib_params,
                            struct xdp_md *ctx, struct iphdr *iph) {
    __builtin_memset(fib_params, 0, sizeof(*fib_params));
    fib_params->family = AF_INET;
    fib_params->ipv4_src = iph->saddr;
    fib_params->ipv4_dst = iph->daddr;
    fib_params->ifindex = ctx->ingress_ifindex;
}

static int fib_lookup_and_forward(struct xdp_md *ctx, struct ethhdr *eth,
                                  struct iphdr *iph) {
    struct bpf_fib_lookup fib_params;
    int ret;

    init_fib_params(&fib_params, ctx, iph);

    ret = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

    switch (ret) {
    case BPF_FIB_LKUP_RET_SUCCESS:
        __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
        return XDP_TX;

    case BPF_FIB_LKUP_RET_BLACKHOLE:
    case BPF_FIB_LKUP_RET_UNREACHABLE:
    case BPF_FIB_LKUP_RET_PROHIBIT:
        bpf_printk("FIB lookup failed (%d), dropping packet", ret);
        return XDP_DROP;

    case BPF_FIB_LKUP_RET_NOT_FWDED:
    case BPF_FIB_LKUP_RET_FWD_DISABLED:
    case BPF_FIB_LKUP_RET_UNSUPP_LWT:
    case BPF_FIB_LKUP_RET_NO_NEIGH:
    case BPF_FIB_LKUP_RET_FRAG_NEEDED:
    case BPF_FIB_LKUP_RET_NO_SRC_ADDR:
        bpf_printk("FIB lookup failed (%d), passing to kernel", ret);
        return XDP_PASS;
    }

    return XDP_PASS;
}

static int is_internal_ip(__u32 ip) {
    return (ip & INTERNAL_MASK) == INTERNAL_SUBNET;
}

struct protocol_info {
    void *header;
    __u16 internal_port;
    __u16 dest_port;
};

static int parse_l4_protocol(struct iphdr *iph, void *data_end,
                             struct protocol_info *info) {
    switch (iph->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcph = (struct tcphdr *)((char *)iph + (iph->ihl << 2));
        if ((void *)(tcph + 1) > data_end) {
            bpf_printk("TCP header boundary check failed");
            return -1;
        }

        info->header = tcph;
        info->internal_port = bpf_ntohs(tcph->source);
        info->dest_port = bpf_ntohs(tcph->dest);
        return 0;
    }

    case IPPROTO_UDP: {
        struct udphdr *udph = (struct udphdr *)((char *)iph + (iph->ihl << 2));
        if ((void *)(udph + 1) > data_end) {
            bpf_printk("UDP header boundary check failed");
            return -1;
        }

        info->header = udph;
        info->internal_port = bpf_ntohs(udph->source);
        info->dest_port = bpf_ntohs(udph->dest);
        return 0;
    }

    case IPPROTO_ICMP: {
        struct icmphdr *icmph =
            (struct icmphdr *)((char *)iph + (iph->ihl << 2));
        if ((void *)(icmph + 1) > data_end) {
            bpf_printk("ICMP header boundary check failed");
            return -1;
        }

        if (icmph->type != ICMP_ECHO && icmph->type != ICMP_ECHOREPLY)
            return -1;

        info->header = icmph;
        info->internal_port = bpf_ntohs(icmph->un.echo.id);
        info->dest_port = 0;
        return 0;
    }

    default:
        return -1;
    }
}

static void set_source_port(struct protocol_info *info, __u8 protocol,
                            __u16 port) {
    switch (protocol) {
    case IPPROTO_TCP:
        ((struct tcphdr *)info->header)->source = bpf_htons(port);
        break;

    case IPPROTO_UDP:
        ((struct udphdr *)info->header)->source = bpf_htons(port);
        break;

    case IPPROTO_ICMP:
        ((struct icmphdr *)info->header)->un.echo.id = bpf_htons(port);
        break;
    }
}

static int update_checksum(struct iphdr *iph, struct protocol_info *info,
                           void *data_end) {
    int ret = -1;

    switch (iph->protocol) {
    case IPPROTO_TCP:
        ret = update_tcp_checksum(iph, info->header, data_end);
        break;

    case IPPROTO_UDP:
        ret = update_udp_checksum(iph, info->header, data_end);
        break;

    case IPPROTO_ICMP:
        ret = update_icmp_checksum(iph, info->header, data_end);
        break;
    }

    if (ret != 0)
        bpf_printk("Failed to update PROTO=%u checksum in", iph->protocol);

    return ret;
}

static int rewrite_outbound_packet(struct iphdr *iph,
                                   struct protocol_info *info, __u16 nat_port,
                                   void *data_end) {
    iph->saddr = PUBLIC_IP;
    set_source_port(info, iph->protocol, nat_port);
    return update_checksum(iph, info, data_end);
}

static void set_dest_port(struct protocol_info *info, __u8 protocol,
                          __u16 port) {
    switch (protocol) {
    case IPPROTO_TCP:
        ((struct tcphdr *)info->header)->dest = bpf_htons(port);
        break;
    case IPPROTO_UDP:
        ((struct udphdr *)info->header)->dest = bpf_htons(port);
        break;
    case IPPROTO_ICMP:
        ((struct icmphdr *)info->header)->un.echo.id = bpf_htons(port);
        break;
    }
}

static int rewrite_inbound_packet(struct iphdr *iph, struct protocol_info *info,
                                  struct port_lookup_value *value,
                                  void *data_end) {
    iph->daddr = value->internal_ip;
    set_dest_port(info, iph->protocol, value->internal_port);
    return update_checksum(iph, info, data_end);
}

static __u16 allocate_port(__u8 protocol) {
    __u32 key = protocol == IPPROTO_TCP ? 0 : (protocol == IPPROTO_UDP ? 1 : 2);
    __u32 *counter = bpf_map_lookup_elem(&port_counters, &key);

    if (!counter) {
        __u32 init_val = 0;
        if (bpf_map_update_elem(&port_counters, &key, &init_val, BPF_ANY) !=
            0) {
            bpf_printk("Failed to initialize port counter");
            return 0;
        }

        counter = bpf_map_lookup_elem(&port_counters, &key);
        if (!counter) {
            bpf_printk("Failed to lookup port counter after init");
            return 0;
        }
    }

    __u32 raw_port = __sync_fetch_and_add(counter, 1);

    if (protocol == IPPROTO_ICMP) {
        return raw_port % 65536;
    } else {
        return TCP_UDP_MIN_PORT + (raw_port % (TCP_UDP_RANGE));
    }
}

static int handle_outbound(struct xdp_md *ctx, struct ethhdr *eth,
                           struct iphdr *iph) {
    struct protocol_info info = {};
    struct nat_session_key key = {};
    struct nat_session_value *value;
    struct port_lookup_key in_key = {};
    struct port_lookup_value in_value = {};
    void *data_end = (void *)(long)ctx->data_end;

    if (parse_l4_protocol(iph, data_end, &info) != 0)
        return XDP_PASS;

    key.protocol = iph->protocol;
    key.internal_ip = iph->saddr;
    key.dest_ip = iph->daddr;
    key.internal_port = info.internal_port;
    key.dest_port = info.dest_port;

    value = bpf_map_lookup_elem(&nat_sessions, &key);

    if (!value) {
        struct nat_session_value new_value = {};
        new_value.nat_external_port = allocate_port(iph->protocol);

        if (new_value.nat_external_port == 0) {
            bpf_printk("Failed to allocate port for protocol %d",
                       iph->protocol);
            return XDP_PASS;
        }

        if (bpf_map_update_elem(&nat_sessions, &key, &new_value, BPF_ANY) !=
            0) {
            bpf_printk("Failed to create session");
            return XDP_PASS;
        }

        in_key.protocol = iph->protocol;
        in_key.dest_port = new_value.nat_external_port;
        in_value.internal_ip = key.internal_ip;
        in_value.internal_port = key.internal_port;
        if (bpf_map_update_elem(&port_lookup, &in_key, &in_value, BPF_ANY) !=
            0) {
            bpf_printk("Failed to create inbound mapping");
            return XDP_PASS;
        }

        value = &new_value;
    }

    if (rewrite_outbound_packet(iph, &info, value->nat_external_port,
                                data_end) != 0)
        return XDP_PASS;

    update_ip_checksum(iph);
    return fib_lookup_and_forward(ctx, eth, iph);
}

static __u16 get_dest_port(struct protocol_info *info, __u8 protocol) {
    switch (protocol) {
    case IPPROTO_TCP:
        return bpf_ntohs(((struct tcphdr *)info->header)->dest);

    case IPPROTO_UDP:
        return bpf_ntohs(((struct udphdr *)info->header)->dest);

    case IPPROTO_ICMP:
        return bpf_ntohs(((struct icmphdr *)info->header)->un.echo.id);

    default:
        return 0;
    }
}

static int handle_inbound(struct xdp_md *ctx, struct ethhdr *eth,
                          struct iphdr *iph) {
    struct protocol_info info = {};
    struct port_lookup_key key = {};
    struct port_lookup_value *value;
    void *data_end = (void *)(long)ctx->data_end;

    if (parse_l4_protocol(iph, data_end, &info) != 0)
        return XDP_PASS;

    key.protocol = iph->protocol;
    key.dest_port = get_dest_port(&info, key.protocol);

    value = bpf_map_lookup_elem(&port_lookup, &key);
    if (!value)
        return XDP_PASS;

    if (rewrite_inbound_packet(iph, &info, value, data_end) != 0)
        return XDP_PASS;

    update_ip_checksum(iph);
    return fib_lookup_and_forward(ctx, eth, iph);
}

static int is_nat_target_outbound(struct iphdr *iph) {
    return is_internal_ip(iph->saddr) && !is_internal_ip(iph->daddr);
}

struct packet_headers {
    struct ethhdr *eth;
    struct iphdr *iph;
};

static __always_inline int is_fragmented(struct iphdr *iph) {
    return !!(iph->frag_off & bpf_htons(IP_MF | IP_OFFSET));
}

static __always_inline int is_supported_l4(struct packet_headers *hdrs) {
    return hdrs->iph->protocol == IPPROTO_TCP ||
           hdrs->iph->protocol == IPPROTO_UDP ||
           hdrs->iph->protocol == IPPROTO_ICMP;
}

static int parse_l2_l3(struct xdp_md *ctx, struct packet_headers *hdrs) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    hdrs->eth = data;
    if ((void *)(hdrs->eth + 1) > data_end)
        return -1;

    if (hdrs->eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    hdrs->iph = (struct iphdr *)(hdrs->eth + 1);
    if ((void *)(hdrs->iph + 1) > data_end)
        return -1;

    if (is_fragmented(hdrs->iph)) {
        bpf_printk("Fragmented packet ignored");
        return -1;
    }

    if (!is_supported_l4(hdrs))
        return 1;

    return 0;
}

SEC("xdp")
int xdp_nat_prog(struct xdp_md *ctx) {
    struct packet_headers hdrs;

    int ret = parse_l2_l3(ctx, &hdrs);
    if (ret < 0)
        return XDP_PASS;

    if (is_nat_target_outbound(hdrs.iph))
        return handle_outbound(ctx, hdrs.eth, hdrs.iph);

    if (hdrs.iph->daddr == PUBLIC_IP) {
        return handle_inbound(ctx, hdrs.eth, hdrs.iph);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
