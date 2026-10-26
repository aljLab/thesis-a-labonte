#include "proxy.h"
/*
MAPS
*/
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, N);
    __type(key, __u32);
    __type(value, struct cached_outer);
} srh_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2 * N + 2);
    __type(key, __u32);
    __type(value, struct mac_entry);
} mac_addr_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2 * N + 1);
    __type(key, __u32);
    __type(value, __u32);
} link_index_table SEC(".maps");


/*
PROGRAMS
*/

SEC("xdp")
int decap(struct xdp_md *ctx)
{
    bpf_printk("Entered decap program");
    /*
    PARSE ETH + IPv6 + SRH + INNER VERSION and PROVE PACKET BOUNDS
    */
    void *start = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;

    struct parsed_srh parsed = {};
    struct parsed_srh *p = &parsed;

    p->eth = start;
    if((void *)((char *)p->eth + sizeof(struct ethhdr)) > end) // try making pointer arithmetic explicit for verifier
        return XDP_DROP;

    p->ip6 = (void *)(p->eth + 1);
    if((void *)((char *)p->ip6 + sizeof(struct ipv6hdr)) > end)
        return XDP_DROP;
    
    p->srh = (void *)(p->ip6 + 1);
    // check for fixed len routing header first [ NextHeader | HdrExtLen | RoutingType | SegmentsLeft ]
    if((void *)((char *)p->srh + 2) > end)
        return XDP_DROP;

    __u8 hdr_ext_len = p->srh->hdrlen;
    // sanity check hdr_ext_len and prove parsing hdr_ext_len bytes after p->srh + 8 is not going across packet boundaries
    if(hdr_ext_len > (__u8)MAX_SEGLIST_LEN/8)
        return XDP_DROP;

    p->srh_len = RH_SIZE + hdr_ext_len * 8;
    __u32 SRH_LEN = p-> srh_len;
    if(SRH_LEN > MAX_SRH_LEN)
        return XDP_DROP;
    
    if((void *)((char *)p->srh + SRH_LEN) > end)
        return XDP_DROP;
    
    p->outer_len = sizeof(struct ipv6hdr) + SRH_LEN;
    __u32 SRV6_LEN = p->outer_len;
    if((void *)((char *)p->ip6 + SRV6_LEN) > end)
        return XDP_DROP;

    if((void *)((char *)p->srh->segments + (SRH_LEN - 8)) > end)
        return XDP_DROP;
    
    // determine inner proto for ethernet header in encap, since it might change in the VNF
    bpf_printk("Decap: Parsed SRH --> SRH_LEN = %u, SRV6_LEN = %u", SRH_LEN, SRV6_LEN);
    /*
    UPDATE THE HEADER IN PACKET
    */
    if(p->srh->segments_left < 1)
        return XDP_PASS; // pass on, seems to be last segment which we can't handle
    p->srh->segments_left--;
    __u8 index = p->srh->segments_left;

    if(index >= (SRH_LEN - 8)/sizeof(struct in6_addr)) // esnure index is not bigger than the actual length of the segment list
        return XDP_DROP;
    
    __builtin_memcpy((void *)&p->ip6->daddr, (void *)&p->srh->segments[index], sizeof(p->ip6->daddr));

    bpf_printk("Decap: Updated the SRH.");

    /* Alternatively: Copy byte by byte
    #pragma unroll
    for(int i = 0; i < MAX_SRH_LEN; i++){
        if(i >= SRH_LEN)
            break;
        p->ip->daddr[i]
    }*/

    /*
    SELECT THE SERVICE CHAIN SLOT
    */
    // just choose first slot for now
    __u32 slot = SLOT;

    /*
    READ CACHED ENTRY
    */
    // |-------ZERO-INITIALIZED-BY-GO-PROGRAM-------|
    struct cached_outer *cached = bpf_map_lookup_elem(&srh_table, &slot);
    if (!cached) 
        return XDP_DROP;
    
    if((void *)cached->bytes + 2 <= end)
        bpf_printk("Looked Up cached header successfully: %02x, %02x", cached->bytes[0], cached->bytes[1]);

    /*
    UPDATE CACHE: COPY IPv6 (outer) + SRH TO CACHE BUFFER
    */
    if(sizeof(cached->bytes) < SRV6_LEN)
        return XDP_DROP;
    /* if((void *)((char *)p->ip6 + SRV6_LEN) > end)
        return XDP_DROP; checked earlier */

    bpf_spin_lock(&cached->lock);
    cached->len = SRV6_LEN;
    __builtin_memcpy((void *)cached->bytes, (void *)p->ip6, SRV6_LEN);
    bpf_spin_unlock(&cached->lock);

    bpf_printk("Decap: updated cache: %02x, %02x", cached->bytes[0], cached->bytes[1]);
    /*
    COPY ETHERNET HEADER IN PACKET INFRONT OF INNER
    */

    __builtin_memcpy((void *)((char *)p->eth + SRV6_LEN), (void *)p->eth, sizeof(struct ethhdr));

    /*
    ADJUST BUFFER SIZE HEAD
    */
    if(bpf_xdp_adjust_head(ctx, SRV6_LEN) < 0)
        return XDP_DROP;
    
    start = (void *)(long)ctx->data;
    end = (void *)(long)ctx->data_end;
    /*
    UPDATE ETHERNET HEADER (src, dst, h_proto)
    */
    struct ethhdr *eth = start;
    if((void *)((char *)eth + sizeof(struct ethhdr)) > end)
        return XDP_DROP;

    // lookup mac addresses
    __u32 src_key = slot;
    __u32 dst_key = N + slot;
    bpf_printk("Retrieving mac's with keys: src (%u), dst (%u)", src_key, dst_key);
    struct mac_entry *src_mac = bpf_map_lookup_elem(&mac_addr_table, &src_key);
    struct mac_entry *dst_mac = bpf_map_lookup_elem(&mac_addr_table, &dst_key);

    if (!src_mac || !dst_mac) 
        return XDP_DROP;

    // replace mac addresses
    __builtin_memcpy((void *)eth->h_source, (void *)src_mac->addr, sizeof(eth->h_source));
    __builtin_memcpy((void *)eth->h_dest, (void *)dst_mac->addr, sizeof(eth->h_dest));

    // update next proto
    if((void *)((char *)eth + sizeof(struct ethhdr) + 1) > end)
        return XDP_DROP;

    __u8 version = *((__u8 *)eth + sizeof(struct ethhdr)) >> 4;
    bpf_printk("DECAP: Inner version is %u", version);
    if(version == 6)
    {
        eth->h_proto = bpf_htons(ETH_P_IPV6);
    }
    else if (version == 4)
    {
        eth->h_proto = bpf_htons(ETH_P_IP);
    } else 
    {
        return XDP_PASS; // or drop?
    }

    /*
    REDIRECT PACKET TO CORRECT INTERFACE
    */

    // lookup interface index
    __u32 *link_index = bpf_map_lookup_elem(&link_index_table, &slot);
    if (!link_index || !*link_index)
        return XDP_DROP;

    return bpf_redirect(*link_index, 0);
}

SEC("xdp")
int encap(struct xdp_md *ctx)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";