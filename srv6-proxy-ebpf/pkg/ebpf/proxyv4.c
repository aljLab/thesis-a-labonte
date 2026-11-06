#include "proxy.h"

/*
Version 4 of the eBPF Proxy. This version is not lane-based like version 3, but based on immutable header fields,
which uniquely identify a service chain.
The key corresponding to one sfc (and stored SRH) are computed based on a mask_map for each supported Layer.
In v4.0.1 support for L3 (IP6, IP4) and L4 (TCP, UDP) is built, but in an easily extensible way.
The proxy relies on two mask_maps (mask_table_l3, mask_table_l4). The user space program and the eBPF program 
must agree which index in the map corresponds to which mask (e.g. [ipv4_mask, ipv6_mask] in mask_table_l3).
The user space loader configures and calculates the masks based on state in the targets spec in the K8s api.
The ebpf program just loads and uses the maps to compute a key to index into the srh_table.
*/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SRH_CACHE_ENTRIES);
    __type(key, struct srh_key);
    __type(value, struct cached_outer); // the cached header structure (lock + len + IPv6 + SRH)
} srh_table SEC(".maps");

// not modified by xdp programs
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2*N + 2); 
    __type(key, __u32);
    __type(value, struct mac_entry); // the mac addresses fromVNF interface belonging to this lane 
} mac_addr_table SEC(".maps");

// not modified by xdp programs
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2*N + 2);
    __type(key, __u32);
    __type(value, __u32); // the associated toVNF interface to put out decapsulated traffic
} link_index_table SEC(".maps");

// not modified by xdp programs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, __u32); 
    __type(value, struct l3_mask_t); 
} mask_table_l3 SEC(".maps");

// not modified by xdp programs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, __u32); 
    __type(value, struct l4_mask_t); 
} mask_table_l4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, MAX_L3_L4_COMBINATIONS + 1);
    __type(key, __u32);
    __type(value, __u32);
} progs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cached_outer_mock);
} scratch_table SEC(".maps");

/*
FUNCTIONS
*/

static __always_inline
int parse_srh(struct parsed_srh *p, void *start, void *end)
{
    p->eth = start;
    if((void *)(p->eth + 1) > end)
        return -1;

    p->ip6 = (void *)(p->eth + 1);
    if((void *)(p->ip6 + 1) > end)
        return -1;

    p->srh = (void *)(p->ip6 + 1);
    // check for fixed len routing header first [ NextHeader | HdrExtLen | RoutingType | SegmentsLeft ]
    if((void *)((char *)p->srh + 8) > end)  
        return -1;

    __u8 hdr_ext_len = p->srh->hdrlen;
    __u8 last_index = p->srh->first_segment;

    p->srh_len = RH_SIZE + hdr_ext_len * 8;
    if(p->srh_len > MAX_SRH_LEN)
        return -1;

    if((void *)((char *)p->srh + p->srh_len) > end)
        return -1;
    
    p->outer_len = sizeof(struct ipv6hdr) + p->srh_len;
    if((void *)((char *)p->ip6 + p->outer_len) > end)
        return -1;

    if((void *)((char *)p->srh->segments + (p->srh_len - 8)) > end)
        return -1;
    
    p->n_segs = (__u32)last_index + 1; //number of segments in segments list
    
    return 0;
}


static __always_inline
int parse_pkt_tcp_ip4(struct pkt_tcp_ip4 *p, void *start, void *end)
{
    p->eth = start;
    if((void *)(p->eth + 1) > end)
        return -1;

    p->ip6 = (void *)(p->eth + 1);
    if((void *)(p->ip6 + 1) > end)
        return -1;

    p->srh = (void *)(p->ip6 + 1);
    // check for fixed len routing header first [ NextHeader | HdrExtLen | RoutingType | SegmentsLeft ]
    if((void *)((char *)p->srh + 8) > end)  
        return -1;

    __u8 hdr_ext_len = p->srh->hdrlen;
    __u8 last_index = p->srh->first_segment;

    p->srh_len = RH_SIZE + hdr_ext_len * 8;
    if(p->srh_len > MAX_SRH_LEN)
        return -1;

    if((void *)((char *)p->srh + p->srh_len) > end)
        return -1;
    
    p->inner_ip4 = (struct iphdr *)((char *)p->srh + p->srh_len);
    if((void *)(p->inner_ip4 + 1) > end)
        return -1;
    
    p->tcp = (struct tcphdr *)(p->inner_ip4 + 1);
    if((void *)(p->tcp + 1) > end)
        return -1;

    return 0;
}
static __always_inline
int parse_pkt_tcp_ip6(struct pkt_tcp_ip6 *p, void *start, void *end)
{
    p->eth = start;
    if((void *)(p->eth + 1) > end)
        return -1;

    p->ip6 = (void *)(p->eth + 1);
    if((void *)(p->ip6 + 1) > end)
        return -1;

    p->srh = (void *)(p->ip6 + 1);
    // check for fixed len routing header first [ NextHeader | HdrExtLen | RoutingType | SegmentsLeft ]
    if((void *)((char *)p->srh + 8) > end)  
        return -1;

    __u8 hdr_ext_len = p->srh->hdrlen;
    __u8 last_index = p->srh->first_segment;

    p->srh_len = RH_SIZE + hdr_ext_len * 8;
    if(p->srh_len > MAX_SRH_LEN)
        return -1;

    if((void *)((char *)p->srh + p->srh_len) > end)
        return -1;
    
    p->inner_ip6 = (struct ipv6hdr *)((char *)p->srh + p->srh_len);
    if((void *)(p->inner_ip6 + 1) > end)
        return -1;
    
    p->tcp = (struct tcphdr *)(p->inner_ip6 + 1);
    if((void *)(p->tcp + 1) > end)
        return -1;

    return 0;
}
static __always_inline
int parse_pkt_udp_ip4(struct pkt_udp_ip4 *p, void *start, void *end)
{
    p->eth = start;
    if((void *)(p->eth + 1) > end)
        return -1;

    p->ip6 = (void *)(p->eth + 1);
    if((void *)(p->ip6 + 1) > end)
        return -1;

    p->srh = (void *)(p->ip6 + 1);
    // check for fixed len routing header first [ NextHeader | HdrExtLen | RoutingType | SegmentsLeft ]
    if((void *)((char *)p->srh + 8) > end)  
        return -1;

    __u8 hdr_ext_len = p->srh->hdrlen;
    __u8 last_index = p->srh->first_segment;

    p->srh_len = RH_SIZE + hdr_ext_len * 8;
    if(p->srh_len > MAX_SRH_LEN)
        return -1;

    if((void *)((char *)p->srh + p->srh_len) > end)
        return -1;
    
    p->inner_ip4 = (struct iphdr *)((char *)p->srh + p->srh_len);
    if((void *)(p->inner_ip4 + 1) > end)
        return -1;
    
    p->udp = (struct udphdr *)(p->inner_ip4 + 1);
    if((void *)(p->udp + 1) > end)
        return -1;

    return 0;
}
static __always_inline
int parse_pkt_udp_ip6(struct pkt_udp_ip6 *p, void *start, void *end)
{
    p->eth = start;
    if((void *)(p->eth + 1) > end)
        return -1;

    p->ip6 = (void *)(p->eth + 1);
    if((void *)(p->ip6 + 1) > end)
        return -1;

    p->srh = (void *)(p->ip6 + 1);
    // check for fixed len routing header first [ NextHeader | HdrExtLen | RoutingType | SegmentsLeft ]
    if((void *)((char *)p->srh + 8) > end)  
        return -1;

    __u8 hdr_ext_len = p->srh->hdrlen;
    __u8 last_index = p->srh->first_segment;

    p->srh_len = RH_SIZE + hdr_ext_len * 8;
    if(p->srh_len > MAX_SRH_LEN)
        return -1;

    if((void *)((char *)p->srh + p->srh_len) > end)
        return -1;
    
    p->inner_ip6 = (void *)((char *)p->srh + p->srh_len);
    if((void *)(p->inner_ip6 + 1) > end)
        return -1;
    
    p->udp = (void*)(p->inner_ip6 + 1);
    if((void *)(p->udp + 1) > end)
        return -1;

    return 0;
}


static __always_inline
int parse_inner_ip4(struct iphdr *ip4, __u32 *l3_len, __u32 *l4_proto, void *end)
{
    if((void *)(ip4 + 1) > end)
        return -1;

    *l3_len = 20; //forget about options for now... (__u32)(ip6->ihl) * 4; 
    *l4_proto = (__u32)ip4->protocol;
    
    return 0;
}

static __always_inline
int parse_inner_ip6(struct ipv6hdr *ip6, __u32 *l3_len, __u32 *l4_proto, void *end)
{
    if((void *)(ip6 + 1) > end)
        return -1;

    *l3_len = sizeof(struct ipv6hdr);
    *l4_proto = (__u32)ip6->nexthdr;
    
    return 0;
}

static __always_inline
int parse_inner_l3(
    char *start, 
    __u32 *inner_l3_version, 
    __u32 *l3_len, 
    __u32 *l4_proto, 
    void *end, 
    struct inner_l3_hdr *inner
)
{
    if((void *)(start + 1) > end){
        return -1;
    }

    *inner_l3_version = *((__u8 *)start) >> 4;

    switch (*inner_l3_version)
    {
    case 4:
        inner->ip4 = (struct iphdr *)(start);
        if(parse_inner_ip4(inner->ip4, l3_len, l4_proto, end) < 0)
            return -1;
        break;
    case 6:
        inner->ip6 = (struct ipv6hdr *)(start);
        if(parse_inner_ip6(inner->ip6, l3_len, l4_proto, end) < 0)
            return -1;
        break;
    
    default:
        break;
    }

    return 0;
}

static __always_inline
int mask_hdr(__u8 *hdr, __u8 *mask, __u32 len, __u8 *dst, void *end)
{
    for (__u32 i = 0; i < MAX_FIXED_HDR_LEN; i++) {
        if (i >= len) break;
        if ((void *)(hdr + i + 1) > end) {
            return -1;
        }
        dst[i] = mask[i] & hdr[i];
    }
    return 0;
}

static __always_inline
struct srh_key *read_key_from_meta(void *meta, void *start)
{
    if ((void *)((char *)meta + sizeof(struct key_meta)) > start)
        return NULL;
    return &((struct key_meta *)meta)->key;
}

static __always_inline
int update_srh(struct parsed_srh *p, void *end)
{   
    if(p->srh_len > MAX_SRH_LEN)
        return -1;
    if((void *)((char *)p->srh + p->srh_len) > end)
        return -1;
    if((void *)((char *)p->srh + 8) > end)
        return -1;
    
    if(p->srh->segments_left < 1)
        return -1; // pass on, seems to be last segment which we can't handle
    p->srh->segments_left--;
    __u8 index = p->srh->segments_left;

    if(index >= (p->srh_len - 8)/sizeof(struct in6_addr)) // ensure index is not bigger than the actual length of the segment list
        return -1;
    if((void *)((struct in6_addr *)p->srh->segments + index + 1) > end)
        return -1;
    
    __builtin_memcpy((void *)&(p->ip6->daddr), (void *)((struct in6_addr *)p->srh->segments + index), sizeof(p->ip6->daddr));

    return 0;
}

static __always_inline
int update_cached_header(struct cached_outer *cached, char *hdr, __u32 len, void *end)
{
    if(len > MAX_CACHED_HDR)
        return -1;
    if(sizeof(cached->bytes) < len) // check capacity (not actual length)
        return -1;
    if((void *)(hdr + len) > end)
        return -1;

    bpf_spin_lock(&cached->lock);
    cached->len = len;

    for(__u32 i = 0; i < MAX_SRH_LEN + sizeof(struct ipv6hdr); i++){
        if(i >= len)
            break;
        if((void *)(hdr + i + 1) > end){
            bpf_spin_unlock(&cached->lock);
            return -1;
        }
        cached->bytes[i] = hdr[i];
    }
    bpf_spin_unlock(&cached->lock);

    return 0;
}

static __always_inline
int cp_ethhdr_in_front_of_inner(struct parsed_srh *p)
{
    __builtin_memcpy((void *)((char *)p->eth + p->outer_len), (void *)p->eth, sizeof(struct ethhdr));
    return 0;
}

/*
ENCAP FUNCTIONS
*/

static __always_inline
int copy_cached_to_buffer(struct ethhdr *eth, struct cached_outer *cached, void *end)
{
    if((void *)(eth + 1) > end)
        return -1;
    __u64 *dst = (__u64 *)(eth + 1);
    if((void *)((char *)dst + cached->len) > end)
        return -1;

    __u32 len = cached->len;
    if(len > MAX_CACHED_HDR)
        len = MAX_CACHED_HDR;
    
    __u32 len_64 = len/8;
    __u32 rest = len%8;

    bpf_spin_lock(&cached->lock);
    // MAX_CACHED_HEADER = 2104 (sizeof(ipv6hdr) + sizeof(ipv6_sr_hdr) + max(segList)) bytes
    // copy cached header in 8-byte blocks fore efficiency
    for(__u32 i = 0; i < MAX_CACHED_HDR / 8; i++){
        if(i >= len_64) break;
        if((void *)(dst + i + 1) > end){
            bpf_spin_unlock(&cached->lock);
            return -1;
        }

        __builtin_memcpy((void *)(dst + i), (void *)((__u64 *)cached->bytes + i), 8);
    }

    // copy the leftover bytes indiviudally
    #pragma unroll
    for(__u32 i = 0; i < 8; i++){
        if(i >= rest) break;
        char *dst_bytes = (char *) (dst + len_64); 
        char *cached_bytes = (char *) (dst + len_64); 
        if((void *)(dst_bytes + i + 1) > end){
            bpf_spin_unlock(&cached->lock);
            return -1;
        }
        dst_bytes[i] = cached_bytes[i];
        //__builtin_memcpy((void *)((char *)dst + len_64*8 + i), (void *)((char *)cached->bytes + len_64*8 + i), 1);
    }
    bpf_spin_unlock(&cached->lock);

    return 0;
}

static __always_inline
int update_ethhdr_encap(struct ethhdr *eth, void *end)
{
    if((void *)(eth + 1) > end)
        return -1;
    
    __u32 src_key = 2*N;
    __u32 dst_key = 2*N + 1;

    struct mac_entry *src = bpf_map_lookup_elem(&mac_addr_table, &src_key);
    struct mac_entry *dst = bpf_map_lookup_elem(&mac_addr_table, &dst_key);

    if(!src || !dst)
        return -1;
    
    // replace mac addresses
    __builtin_memcpy((void *)eth->h_source, (void *)src->addr, sizeof(eth->h_source));
    __builtin_memcpy((void *)eth->h_dest, (void *)dst->addr, sizeof(eth->h_dest));

    // set next proto to IPv6
    eth->h_proto = bpf_htons(ETH_P_IPV6);

    return 0;
}

static __always_inline
int update_nxthdr(struct ethhdr *eth, void *end, __u8 version)
{
    if((void *) eth + 1 > end)
        return -1;

    struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
    
    if((void *)(ip6 + 1) > end)
        return -1;
    
    struct ipv6_sr_hdr *srh = (struct ipv6_sr_hdr *)(ip6 + 1);
    if((void *)((char *)srh + 1) > end)
        return -1;
    
    srh->nexthdr = version;
    switch (version)
    {
    case 4:
        srh->nexthdr = IPPROTO_IPIP;
        break;
    case 6:
        srh->nexthdr = IPPROTO_IPV6;
    default:
        break;
    }
    return 0;
}

static __always_inline
int update_eth_hdr(void *start, void *end)
{
    struct ethhdr *eth = start;
    if((void *)((char *)eth + sizeof(struct ethhdr)) > end)
        return -1;

    // lookup mac addresses
    __u32 src_key = 0;
    __u32 dst_key = 1;
    struct mac_entry *src_mac = bpf_map_lookup_elem(&mac_addr_table, &src_key);
    struct mac_entry *dst_mac = bpf_map_lookup_elem(&mac_addr_table, &dst_key);

    if (!src_mac || !dst_mac) 
        return -1;

    // replace mac addresses
    __builtin_memcpy((void *)eth->h_source, (void *)src_mac->addr, sizeof(eth->h_source));
    __builtin_memcpy((void *)eth->h_dest, (void *)dst_mac->addr, sizeof(eth->h_dest));

    // update next proto
    if((void *)((char *)eth + sizeof(struct ethhdr) + 1) > end)
        return -1;

    __u8 version = *((__u8 *)eth + sizeof(struct ethhdr)) >> 4;
    if(version == 6)
    {
        eth->h_proto = bpf_htons(ETH_P_IPV6);
    }
    else if (version == 4)
    {
        eth->h_proto = bpf_htons(ETH_P_IP);
    } else 
    {
        return -1;
    }

    return 0;
}

static __always_inline
int get_hdr_size_for_key_calc(__u32 l4_proto, __u32 *l4_key_size)
{
    switch (l4_proto)
    {
    case IPPROTO_TCP:
        *l4_key_size = sizeof(struct tcphdr);
        break;
    case IPPROTO_UDP:
        *l4_key_size = sizeof(struct udphdr);
        break;
    default:
        break;
    }

    if(l4_key_size < 0)
        return -1;
    
    return 0;
}

/*
XDP PROGRAMS
*/

SEC("xdp")
int proxy_ingress(struct xdp_md *ctx)
{
    bpf_printk("Entered proxy ingress;");
    if(bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct key_meta)) < 0)
        return XDP_ABORTED;
    
    void *start = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    void *meta = (void *)(long)ctx->data_meta;

    if ((void *)((char *)meta + sizeof(struct key_meta)) > start)
        return XDP_ABORTED;

    struct key_meta *key_meta_p = (struct key_meta *)meta;
    struct srh_key *key = (struct srh_key *)&(key_meta_p->key);
    
    struct parsed_srh p;
    if(parse_srh(&p, start, end) < 0)
        return XDP_DROP;

    bpf_printk("Ingress: parsed p->srh_len=%u, p->outer_len=%u;", p.srh_len, p.outer_len);

    __u32 inner_l3_version = -1;
    __u32 l3_len = -1;
    __u32 l4_proto = -1; // should be 6 (TCP) or 17 (UDP)
    char *inner_start = (char *)((char *)p.srh + p.srh_len);
    struct inner_l3_hdr inner = {0};
    if(parse_inner_l3(inner_start, &inner_l3_version, &l3_len, &l4_proto, end, &inner) < 0 || l3_len < 0)
        return XDP_DROP;

    bpf_printk("Ingress: parsed L3 version=%u, len=%u, next_proto=%u;", inner_l3_version, l3_len, l4_proto);
    if(l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP){
        if(l4_proto == 43)
            bpf_printk("Weird 43 err happened again, not decapsulating?");
        return XDP_ABORTED;
    }
    struct l3_mask_t *l3_mask = bpf_map_lookup_elem(&mask_table_l3, &inner_l3_version);

    if(!l3_mask)
        return XDP_DROP;

    bpf_printk("Ingress: Determining inner header");
    // write masked value directly into key->l3 (in data-meta)
    __u8 *inner_hdr;
    switch (inner_l3_version)
    {
    case 4:
            inner_hdr = (__u8 *)inner.ip4;
        break;
    case 6:
            inner_hdr = (__u8 *)inner.ip6;
        break;
    
    default:
        return -1;
        break;
    }
    bpf_printk("Ingress: Determining inner header");

    if (!inner_hdr)
        return XDP_DROP;
    bpf_printk("Ingress: masking l3");
    if(mask_hdr(inner_hdr, (__u8 *)l3_mask->bytes, l3_len, (__u8 *)key->l3, end) < 0){
        return XDP_DROP;
    }
    // order in main setup: [0]ip4/tcp [1]ip6/tcp [2]ip4/udp [3]ip6/udp
    bpf_printk("Tailcalling;");
    if(inner_l3_version == 4)
    {
        if(l4_proto == IPPROTO_TCP)
        {
            bpf_tail_call(ctx, &progs, 0);
        } 
        else if (l4_proto == IPPROTO_UDP)
        {
            bpf_tail_call(ctx, &progs, 2);
        } else 
        {
            return XDP_DROP;
        }
    } else if (inner_l3_version == 6)
    {
        if(l4_proto == IPPROTO_TCP)
        {
            bpf_tail_call(ctx, &progs, 1);
        } 
        else if (l4_proto == IPPROTO_UDP)
        {
            bpf_tail_call(ctx, &progs, 3);
        } else 
        {
            return XDP_DROP;
        }
    }

    return XDP_ABORTED;

}

SEC("xdp")
int proxy_egress(struct xdp_md *ctx)
{   
    bpf_printk("Entered Egress");
    void *start = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = start;
    if((void *)(eth + 1) > end)
        return XDP_DROP;
    
    // parse L3
    __u32 inner_l3_version = -1;
    __u32 l3_len = -1;
    __u32 l4_proto = -1; // should be 6 (TCP) or 17 (UDP)
    struct inner_l3_hdr inner = {0};
    char *inner_start = (char *)(eth + 1);
    if(parse_inner_l3(inner_start, &inner_l3_version, &l3_len, &l4_proto, end, &inner) < 0){
        bpf_printk("Dropped in parse_inner_l3...");
        return XDP_DROP;
    }

    bpf_printk("Egress: l4_proto %u, version %u", l4_proto, inner_l3_version);

    if(l4_proto != IPPROTO_TCP && l4_proto != IPPROTO_UDP){
        if(l4_proto == 43)
            bpf_printk("Weird 43 err happened again, not decapsulating?");
        return XDP_ABORTED;
    }

    struct l3_mask_t *l3_mask = bpf_map_lookup_elem(&mask_table_l3, &inner_l3_version);

    if(!l3_mask)
        return XDP_DROP;

    __u8 *inner_hdr;
    switch (inner_l3_version)
    {
    case 4:
            inner_hdr = (__u8 *)inner.ip4;
        break;
    case 6:
            inner_hdr = (__u8 *)inner.ip6;
        break;
    
    default:
        return -1;
        break;
    }

    if (!inner_hdr)
        return XDP_DROP;
    
    struct srh_key key = {0};
    
    if(mask_hdr(inner_hdr, (__u8 *)l3_mask->bytes, l3_len, (__u8 *)key.l3, end) < 0){
        return XDP_DROP;
    }

    if((void *)((char *)inner_start + l3_len) > end) // what about options?
        return XDP_DROP;
    
    char *start_l4 = (char *)((char *)inner_start + l3_len);

    __u32 l4_key_size = -1;
    if(get_hdr_size_for_key_calc(l4_proto, &l4_key_size) < 0 || l4_key_size < 0)
        return XDP_DROP;

    struct l4_mask_t *l4_mask = bpf_map_lookup_elem(&mask_table_l4, &l4_proto);
    if(!l4_mask)
        return XDP_DROP;

    if(mask_hdr((__u8 *)start_l4, (__u8 *)l4_mask->bytes, l4_key_size, (__u8 *)key.l4, end) < 0)
        return XDP_DROP;
    
    // from v3
    struct cached_outer *cached = bpf_map_lookup_elem(&srh_table, &key);
    if(!cached){
        bpf_printk("No cached entry was found with calculated key, did something change fields?");
        return XDP_DROP; // if no entry is found, something must have gone wrong -> drop the packet
    }

    __u32 len = cached->len;
    if (len > MAX_CACHED_HDR)
        len = MAX_CACHED_HDR;
    
    if(bpf_xdp_adjust_head(ctx, -(int)len) < 0)
        return XDP_DROP;

    start = (void *)(long)ctx->data;
    end = (void *)(long)ctx->data_end;

    if ((void *)((char *)start + sizeof(struct ethhdr)) > end)
        return XDP_DROP;

    barrier_var(len);
    eth = (struct ethhdr *)((char *)start + len);

    if ((void *)(eth + 1) > end)
        return XDP_DROP;

    __builtin_memcpy(start, eth, sizeof(struct ethhdr));

    eth = (struct ethhdr *)start;

    if(update_ethhdr_encap(eth, end) < 0)
        return XDP_DROP;
    
    // copy cached->bytes in front of inner packet
    if(copy_cached_to_buffer(eth, cached, end) < 0)
        return XDP_DROP;
    
    // update nexthdr based on version observed previously
    if(update_nxthdr(eth, end, inner_l3_version) < 0)
        return XDP_DROP;

    // lookup index of dispatcher veth
    __u32 link_index_key = 2*N; // per convention the dispatcher veths idx is at index <2N>
    __u32 *link_index = bpf_map_lookup_elem(&link_index_table, &link_index_key);
    if(!link_index)
        return XDP_DROP;
    bpf_printk("Leaving egress.");
    return bpf_redirect(*link_index, 0);
}

SEC("xdp")
int tcp_in_ip4(struct xdp_md *ctx)
{
    bpf_printk("Entered tcp_in_ip4");
    void *start = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    void *meta = (void *)(long)ctx->data_meta;

    struct srh_key *key = read_key_from_meta(meta, start); 
    if(!key)
        return XDP_ABORTED;
    struct pkt_tcp_ip4 pkt;
    if(parse_pkt_tcp_ip4(&pkt, start, end) < 0)
        return XDP_DROP;
    __u32 map_key = IPPROTO_TCP;
    struct l4_mask_t *l4_mask = bpf_map_lookup_elem(&mask_table_l4, &map_key);
    if(!l4_mask)
        return XDP_DROP;

    if(mask_hdr((__u8 *)pkt.tcp, (__u8 *)l4_mask->bytes, sizeof(struct tcphdr), (__u8 *)key->l4, end) < 0)
        return XDP_DROP;
    
    bpf_tail_call(ctx, &progs, MAX_L3_L4_COMBINATIONS);

    return XDP_ABORTED;
}
SEC("xdp")
int udp_in_ip4(struct xdp_md *ctx)
{
    bpf_printk("Entered udp_in_ip4");
    void *start = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    void *meta = (void *)(long)ctx->data_meta;

    struct srh_key *key = read_key_from_meta(meta, start); 
    if(!key)
        return XDP_ABORTED;
    struct pkt_udp_ip4 pkt;
    if(parse_pkt_udp_ip4(&pkt, start, end) < 0)
        return XDP_DROP;
    __u32 map_key = IPPROTO_UDP;
    struct l4_mask_t *l4_mask = bpf_map_lookup_elem(&mask_table_l4, &map_key);
    if(!l4_mask)
        return XDP_DROP;

    if(mask_hdr((__u8 *)pkt.udp, (__u8 *)l4_mask->bytes, sizeof(struct udphdr), (__u8 *)key->l4, end) < 0)
        return XDP_DROP;
    
    bpf_tail_call(ctx, &progs, MAX_L3_L4_COMBINATIONS);

    return XDP_ABORTED;
}
SEC("xdp")
int tcp_in_ip6(struct xdp_md *ctx)
{
    bpf_printk("Entered tcp_in_ip6");
    void *start = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    void *meta = (void *)(long)ctx->data_meta;

    struct srh_key *key = read_key_from_meta(meta, start); 
    if(!key)
        return XDP_ABORTED;
    struct pkt_tcp_ip6 pkt;
    if(parse_pkt_tcp_ip6(&pkt, start, end) < 0)
        return XDP_DROP;
    __u32 map_key = IPPROTO_TCP;
    struct l4_mask_t *l4_mask = bpf_map_lookup_elem(&mask_table_l4, &map_key);
    if(!l4_mask)
        return XDP_DROP;

    if(mask_hdr((__u8 *)pkt.tcp, (__u8 *)l4_mask->bytes, sizeof(struct tcphdr), (__u8 *)key->l4, end) < 0)
        return XDP_DROP;
    
    bpf_tail_call(ctx, &progs, MAX_L3_L4_COMBINATIONS);

    return XDP_ABORTED;
}
SEC("xdp")
int udp_in_ip6(struct xdp_md *ctx)
{
    bpf_printk("Entered udp_in_ip6");
    void *start = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    void *meta = (void *)(long)ctx->data_meta;

    struct srh_key *key = read_key_from_meta(meta, start); 
    if(!key)
        return XDP_ABORTED;
    struct pkt_udp_ip6 pkt;
    if(parse_pkt_udp_ip6(&pkt, start, end) < 0)
        return XDP_DROP;
    __u32 map_key = IPPROTO_UDP;
    struct l4_mask_t *l4_mask = bpf_map_lookup_elem(&mask_table_l4, &map_key);
    if(!l4_mask)
        return XDP_DROP;

    if(mask_hdr((__u8 *)pkt.udp, (__u8 *)l4_mask->bytes, sizeof(struct udphdr), (__u8 *)key->l4, end) < 0)
        return XDP_DROP;
    
    bpf_tail_call(ctx, &progs, MAX_L3_L4_COMBINATIONS);

    return XDP_ABORTED;
}

SEC("xdp")
int decap(struct xdp_md *ctx)
{   
    bpf_printk("entered decap tailcall...");
    void *start = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    void *meta = (void *)(long)ctx->data_meta;

    struct srh_key *key = read_key_from_meta(meta, start); 
    if(!key)
        return XDP_ABORTED;

    struct parsed_srh parsed = {};
    struct parsed_srh *p = &parsed;
    if(parse_srh(p, start, end) < 0)
        return XDP_DROP;

    if(update_srh(p, end) < 0)
        return XDP_DROP;

    struct cached_outer *cached;
    cached = bpf_map_lookup_elem(&srh_table, key);
    if(!cached){
        // not initialized -> zero init from scratch map to save stack space
        __u32 zero_key = 0;
        struct cached_outer_mock *zeroed = bpf_map_lookup_elem(&scratch_table, &zero_key);
        if(!zeroed)
            return XDP_DROP;
        bpf_map_update_elem(&srh_table, key, zeroed->bytes, BPF_NOEXIST);
        cached = bpf_map_lookup_elem(&srh_table, key);
        if(!cached)
            return XDP_DROP;
    }
    if(update_cached_header(cached, (char *)p->ip6, p->outer_len, end) < 0)
        return XDP_DROP;

    if(cp_ethhdr_in_front_of_inner(p))
    // get dst/src mac addresses update eth header h_proto in packet

     if(update_eth_hdr(p->eth, end) < 0)
        return XDP_DROP;

    if(bpf_xdp_adjust_head(ctx, p->outer_len) < 0)
        return XDP_DROP;

    // refetch pointers/reparse needed headers
    start = (void *)(long)ctx->data;
    end = (void *)(long)ctx->data_end;

    if(update_eth_hdr(start, end) < 0)
        return XDP_DROP;
    
    bpf_printk("Ingress: srh_len: %u, outer_len: %u", p->srh_len, p->outer_len);

    // fetch linkIndex of outgoing lane interface
    __u32 link_key = 0;
    __u32 *link_index = bpf_map_lookup_elem(&link_index_table, &link_key);
    
    if(!link_index || !*link_index)
        return XDP_DROP;
    return bpf_redirect(*link_index, 0);
}

char LICENSE[] SEC("license") = "GPL";