
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef N
#error "Compile with -DN=<number of service chains>"
#endif

#ifndef SLOT
#define SLOT 0
#endif

#define MAX_SRH_LEN 2048 // 256 (8-bit hdrextLen field) 8-byte blocks 
#define MAX_CACHED_HDR (sizeof(struct ipv6hdr) + MAX_SRH_LEN)
#define FNV_32_PRIME 0x01000193
#define FNV1_32_INIT 0x811C9DC5

struct cached_outer {
    struct bpf_spin_lock lock;
    __u16 len;
    __u16 pad;
    __u8 bytes[MAX_CACHED_HDR];
};

struct mac_entry {
    __u8 addr[6];
    __u8 pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, N);
    __type(key, __u32);
    __type(value, struct cached_outer);
} srh_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2 * N + 1);
    __type(key, __u32);
    __type(value, __u32);
} link_index_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2 * N + 2);
    __type(key, __u32);
    __type(value, struct mac_entry);
} mac_addr_table SEC(".maps");

/* use this per-cpu map to move the parsed srh into while decaping
struct {
    __uint(type, BPF_MAP_PERCPU_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct parsed_srh);
} scratch_table SEC(".maps");*/

struct ipv6_sr_hdr {
	__u8	nexthdr;
	__u8	hdrlen;
	__u8	type;
	__u8	segments_left;
	__u8	first_segment; /* Represents the last_entry field of SRH */
	__u8	flags;
	__u16	tag;

	struct in6_addr segments[];
};

struct parsed_srh {
    struct ethhdr *eth;
    struct ipv6hdr *ip6;
    struct ipv6_sr_hdr *srh;
    __u32 srh_len;
    __u32 outer_len;
    __u16 next_proto;
};

static __always_inline int
parse_srh(struct xdp_md *ctx, struct parsed_srh *p)
{
    void *data = (void *)(long)ctx->data;
    void *end  = (void *)(long)ctx->data_end;

    p->eth = data;
    if ((void *)(p->eth + 1) > end)
        return -1;

    if (p->eth->h_proto != bpf_htons(ETH_P_IPV6)) // more than one byte -> care about byte order
        return -1;

    // advance cursor to start of outer IPv6
    p->ip6 = (void *)(p->eth + 1);

    // check buffer bounds
    if ((void *)(p->ip6 + 1) > end)
        return -1;

    if (p->ip6->version != 6 ||
        p->ip6->nexthdr != IPPROTO_ROUTING)
        return -1;
    
    p->srh = (void *)(p->ip6 + 1);
    if ((void *)p->srh + 8 > end)
        return -1;

    if (p->srh->type != 4)
        return -1;

    p->srh_len = ((__u32)p->srh->hdrlen + 1) * 8; 

    if (p->srh_len < 8 || p->srh_len > MAX_SRH_LEN)
        return -1;

    if ((void *)p->srh + p->srh_len > end)
        return -1;

    p->outer_len = sizeof(struct ipv6hdr) + p->srh_len;

    // get the inner IP version
    if((void *)(const __u8 *)p->srh + p->srh_len + 8 > end) // +8 or without? does end point to the last byte or the first non-buffer byte?
        return -1;

    __u8 version = (*(const __u8 *)((const __u8 *)p->srh + p->srh_len)) >> 4;

    // find the next proto value based on the version
    if (version == 6){
        p->next_proto = ETH_P_IPV6;
    }
    else if (version == 4)
    {
        p->next_proto = ETH_P_IP;
    }
    else
    {
        return -1;
    }

    return 0;
}

static __always_inline int // try not inlining here to clean up unused variables with stack frame on return
select_slot(struct parsed_srh *p, __u32 *slot)
{
    // determine which slot to use from srh: hash the header % N -> optimize by choosing subset of header
    // optimally the assignment is uniformly distributed
    __u32 hash = FNV1_32_INIT;

    const __u8 *bytes = (const __u8 *)p->srh;

    #pragma unroll
    for (int i = 0; i < MAX_SRH_LEN; i++) {
        if((__u32)i < p->srh_len)
            break;
        hash ^= bytes[i];
        hash *= FNV_32_PRIME;
    }

    *slot = hash % N;

    return 0;
}


static __always_inline int
srh_advance(struct ipv6hdr *ip6, struct ipv6_sr_hdr *srh, void *data_end, __u32 srh_len)
{
    __u32 left = srh->segments_left;
    __u32 first = srh->first_segment;

    if (left == 0)
        return -1;

    if (left - 1 > first)
        return -1;

    __u32 seg_idx = left - 1;

    // Bound the index for the verifier and limit it to the SRH.
    if (seg_idx >= MAX_SRH_LEN / sizeof(struct in6_addr))
        return -1;

    __u32 seg_offset = sizeof(struct ipv6_sr_hdr) + seg_idx * sizeof(struct in6_addr);

    if (seg_offset + sizeof(struct in6_addr) > srh_len)
        return -1;

    const __u8 *seg = (const __u8 *)srh + seg_offset;

    if (seg + sizeof(struct in6_addr) > (const __u8 *)data_end)
        return -1;

    // All checks passed; now update the packet.
    // srh->segments_left = left - 1;
    __builtin_memcpy(&ip6->daddr, seg, sizeof(ip6->daddr));

    return 0;
}

SEC("xdp")
int decap(struct xdp_md *ctx)
{
    struct parsed_srh p = {}; // stack +20
    
    if (parse_srh(ctx, &p) < 0)
    return XDP_PASS;
    
    void *end  = (void *)(long)ctx->data_end;
    // decrement segmentsLeft and update the DA 
    if (srh_advance(p.ip6, p.srh, end, p.srh_len) < 0)
        return XDP_DROP;

    __u32 slot; // stack
    if (select_slot(&p, &slot) < 0)
        return XDP_PASS;

    if (p.outer_len > MAX_CACHED_HDR)
        return XDP_DROP;

    /**
     * LOOKUP CACHED HEADER -> UPDATE OR INIT
     */
    struct cached_outer *cached = bpf_map_lookup_elem(&srh_table, &slot); // stack +4

    if (!cached) 
        return XDP_DROP;

    
    // prove reading in packet bounds
    if (p.srh_len > MAX_SRH_LEN)
        return XDP_DROP;
    
    const __u8 *shr_bytes = (const __u8 *)p.srh;
    
    if (shr_bytes + p.srh_len > (const __u8 *)end)
        return XDP_DROP;
    
    if ((void *)(p.ip6 + 1) > end)
        return XDP_DROP;
        
    // prove copying within cache bounds
    if((void *)cached->bytes + sizeof(struct ipv6hdr) + p.srh_len > end)
        return XDP_DROP;


    bpf_spin_lock(&cached->lock);
        cached->len = p.outer_len;
        __builtin_memcpy(cached->bytes, p.ip6, sizeof(struct ipv6hdr));

        #pragma unroll
        for(int i = 0; i < MAX_SRH_LEN; i++){
            if((__u32)i >= p.srh_len)
                break;
            cached->bytes[sizeof(struct ipv6hdr) + i] = shr_bytes[i];
    }

    bpf_spin_unlock(&cached->lock);
    /*
    * MOVE + UPDATE ETHERNET HEADER
    */
    void *data = (void *)(long)ctx->data; // stack +4

    __builtin_memcpy((char *)data + p.outer_len, p.eth, sizeof(struct ethhdr));

    if (bpf_xdp_adjust_head(ctx, p.outer_len) < 0) // shrink buffer (front) by sizeof(IPv6+SRH)
        return XDP_DROP;

    data = (void *)(long)ctx->data; // stack +0
    end = (void *)(long)ctx->data_end; // stack +4

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end)
        return XDP_DROP;

    __u32 src_key, dst_key; // stack +8
    src_key = slot; 
    dst_key = N + slot;

    // lookup macaddrs of outgoing interface and expected return interface
    struct mac_entry *src_mac = bpf_map_lookup_elem(&mac_addr_table, &src_key);
    struct mac_entry *dst_mac = bpf_map_lookup_elem(&mac_addr_table, &dst_key);

    if (!src_mac || !dst_mac)
        return XDP_DROP;

    __builtin_memcpy(eth->h_source, src_mac->addr, 6);
    __builtin_memcpy(eth->h_dest, dst_mac->addr, 6);
    eth->h_proto = bpf_htons(p.next_proto);

    /*
    * FIND OUTGOING INTERFACE'S LINK INDEX
    */

    __u32 *ifindex =
        bpf_map_lookup_elem(&link_index_table, &slot);

    if (!ifindex || !*ifindex)
        return XDP_DROP;

    return bpf_redirect(*ifindex, 0);
}

SEC("xdp")
int encap(struct xdp_md *ctx)
{
    const __u32 slot = SLOT;

    if (slot >= N)
        return XDP_ABORTED;

    struct cached_outer *cached = bpf_map_lookup_elem(&srh_table, &slot);

    // drop all packets if no encapsulation header is set
    if (!cached)
        return XDP_DROP;

    __u16 hdr_len;

    bpf_spin_lock(&cached->lock);
    hdr_len = cached->len;
    bpf_spin_unlock(&cached->lock);

    if (hdr_len < sizeof(struct ipv6hdr) + 8 || hdr_len > MAX_CACHED_HDR)
        return XDP_DROP;

    void *data = (void *)(long)ctx->data;
    void *end  = (void *)(long)ctx->data_end;

    struct ethhdr *inner_eth = data;
    if ((void *)(inner_eth + 1) > end)
        return XDP_DROP;

    __u16 inner_proto = inner_eth->h_proto;
    __u32 inner_len = (__u32)((char *)end - (char *)data) - sizeof(struct ethhdr);

    __u8 inner_nexthdr;

    // TODO update nextHdr in decap and skip here
    if (inner_proto == bpf_htons(ETH_P_IP))
        inner_nexthdr = IPPROTO_IPIP;
    else if (inner_proto == bpf_htons(ETH_P_IPV6))
        inner_nexthdr = IPPROTO_IPV6;
    else
        return XDP_PASS;

    if (inner_len + hdr_len - sizeof(struct ipv6hdr) > 65535) // why subtracting sizeof(ipv6hdr)?
        return XDP_DROP;

    // |---FREE---|---ETH---|---INNER_IP---|
    if (bpf_xdp_adjust_head(ctx, -(__s32)hdr_len) < 0)
        return XDP_DROP;

    data = (void *)(long)ctx->data;
    end  = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    inner_eth = (void *)((char *)data + hdr_len);

    if ((void *)(eth + 1) > end || (void *)(inner_eth + 1) > end)
        return XDP_DROP;

    // |--ETH--|-|---OLD-ETH---|---INNER_IP---|
    __builtin_memcpy(eth, inner_eth, sizeof(*eth));

    cached = bpf_map_lookup_elem(&srh_table, &slot);
    if (!cached)
        return XDP_DROP;

    bpf_spin_lock(&cached->lock);

    if (cached->len != hdr_len) {
        // header length changed after reading length -> packet would be incorrectly encaped -> DROP
        bpf_spin_unlock(&cached->lock);
        return XDP_DROP;
    }

    // |--ETH--|---SRv6---|---INNER_IP---|
    if((char *)data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > (char *)end)
        return XDP_DROP;
    
    //if((char *)cached->bytes + sizeof(struct ipv6hdr) > (char *)cached + sizeof(struct cached_outer))
    //    return XDP_DROP;

    __builtin_memcpy((char *)data + sizeof(struct ethhdr), cached->bytes, sizeof(struct ipv6hdr));

    __u8 *skb_srh = (__u8 *)data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
    const __u8 *cached_srh_bytes = (__u8 *) (cached->bytes + sizeof(struct ipv6hdr));

    __u32 srh_len = hdr_len - sizeof(struct ipv6hdr);

    if((void *)(skb_srh + srh_len) > end)
        return XDP_DROP;

    #pragma unroll
    for(int i = 0; i < MAX_SRH_LEN; i++){
        if ((__u32)i >= srh_len)
            break;
        
        skb_srh[i] = cached_srh_bytes[i];
    }

    bpf_spin_unlock(&cached->lock);

    /* REPARSE PACKET AND UPDATE HEADER VALUES THAT MIGHT HAVE CHANGED */
    data = (void *)(long)ctx->data;
    end  = (void *)(long)ctx->data_end;

    eth = data;
    struct ipv6hdr *ip6 = (void *)((char *)data + sizeof(struct ethhdr));

    if ((void *)(ip6 + 1) > end)
        return XDP_DROP;

    struct ipv6_sr_hdr *srh = (void *)(ip6 + 1);
    srh_len = hdr_len - sizeof(struct ipv6hdr);

    if ((void *)srh + srh_len > end)
        return XDP_DROP;

    // ip6->nexthdr = IPPROTO_ROUTING;
    ip6->payload_len = bpf_htons(srh_len + inner_len);
    srh->nexthdr = inner_nexthdr;

    __u32 src_key, dst_key;
    src_key = 2*N ; // iml0
    dst_key = 2*N + 1; // gw

    // lookup macaddrs of outgoing interface and expected return interface
    struct mac_entry *src_mac = bpf_map_lookup_elem(&mac_addr_table, &src_key);
    struct mac_entry *dst_mac = bpf_map_lookup_elem(&mac_addr_table, &dst_key);

    if (!src_mac || !dst_mac)
        return XDP_DROP;

    __builtin_memcpy(eth->h_source, src_mac->addr, 6);
    __builtin_memcpy(eth->h_dest, dst_mac->addr, 6);
    eth->h_proto = ETH_P_IPV6;

    __u32 iml_key = 2 * N; // iml0
    __u32 *ifindex = bpf_map_lookup_elem(&link_index_table, &iml_key);

    if (!ifindex || !*ifindex)
        return XDP_DROP;

    return bpf_redirect(*ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
