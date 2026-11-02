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
    __uint(max_entries, 2 * N + 2);
    __type(key, __u32);
    __type(value, __u32);
} link_index_table SEC(".maps");

// per cpu map to store the sfc's momentarily occupying the lanes: { lane_index -> sfc }
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, N);
    __type(key, __u32);
    __type(value, struct sfc_t);
} sfc_lane_map SEC(".maps");

// one-entry clock map storing a monotonic clock value increasing on each SRv6 packet
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} clock_map SEC(".maps");


/*
FUNCTIONS
*/

__u32 assign_lane(struct in6_addr *new_segs, __u32 n_seg, __u64 *clock)
{
    __s32 oldest_lane; // stores the lane to be evicted if new_segs is a new SFC
    __u64 oldest_time = 1ULL << 63; // initialize to max of allowed distance between two packets
    struct sfc_t *oldest_sfc;

    // proof length of new_segs
    __u32 NEW_SEG_LEN = n_seg;
    if(NEW_SEG_LEN < 1 || NEW_SEG_LEN > 128)
        return -1;

    for(__s32 i = 0; i < N; i++){
        struct sfc_t *sfc = bpf_map_lookup_elem(&sfc_lane_map, &i); // initialized with 

        if (!sfc)
            return -1;
        
        if(sfc->last_seen == 0){ // means lane was not assigned yet and is free
            __builtin_memcpy((void *)sfc->segments, (void *)new_segs, NEW_SEG_LEN);
            sfc->n_segs = n_segs;
            sfc->last_seen = *clock;
            
            return i;
        }
        
        __u32 SEG_LEN = sfc->n_segs;
        
        if((SEG_LEN < 1 || SEG_LEN > 128) || SEG_LEN != NEW_SEG_LEN)
            continue;

        // update eviction candidate (account for clock wrap)
         if((__s64)(sfc->last_seen - oldest_time) < 0){
            oldest_time = sfc->last_seen;
            oldest_lane = i;
            oldest_sfc = sfc; // kep reference eviction candidate
        }
        if (__builtin_memcmp(new_segs, sfc->segments, SEG_LEN) == 0) {
            sfc->n_segs = n_segs;
            sfc->last_seen = *clock;
            return i;
        }
    }

    // if no stored srh matches and no lane is free -> new sfc -> evict oldest lane
    __builtin_memcpy((void *)oldest_sfc->segments, (void *)new_segs, NEW_SEG_LEN);
    oldest_sfc->last_seen = *clock;
    oldest_sfc->n_segs = n_segs;
    return oldest_lane;
}

/*
PROGRAMS
*/

SEC("xdp")
int decap(struct xdp_md *ctx)
{   
    bpf_printk("Entered decap program");
    __u32 clock_index = 0;
    __u64 *clock = bpf_map_lookup_elem(&clock_map, &clock_index);

    if(!clock){
        bpf_printk("Could not get clock in decap.");
        return XDP_DROP;
    }
    /*
    PARSE ETH + IPv6 + SRH + INNER VERSION and PROVE PACKET BOUNDS
    */
    void *start = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;

    struct parsed_srh parsed = {};
    struct parsed_srh *p = &parsed;

    bpf_printk("starting to parse headers...");

    p->eth = start;
    if((void *)((char *)p->eth + sizeof(struct ethhdr)) > end){ // try making pointer arithmetic explicit for verifier
        bpf_printk("Failed ETH size check -> dropping");
        return XDP_DROP;
    }

    p->ip6 = (void *)(p->eth + 1);
    if((void *)((char *)p->ip6 + sizeof(struct ipv6hdr)) > end){
        bpf_printk("Failed IP6 size check -> dropping");    
        return XDP_DROP;
    }
    p->srh = (void *)(p->ip6 + 1);
    // check for fixed len routing header first [ NextHeader | HdrExtLen | RoutingType | SegmentsLeft ]
    if((void *)((char *)p->srh + 8) > end){
        bpf_printk("Failed fixed len srh size check -> dropping");    
        return XDP_DROP;
    }

    __u8 hdr_ext_len = p->srh->hdrlen;
    // sanity check hdr_ext_len and prove parsing hdr_ext_len bytes after p->srh + 8 is not going across packet boundaries
    /* if(hdr_ext_len > (__u16)(MAX_SEGLIST_LEN / 8)){
        bpf_printk("hdr len %u does not check out -> dropping", hdr_ext_len);    
        return XDP_DROP;
    } */

    p->srh_len = RH_SIZE + hdr_ext_len * 8;
    __u32 SRH_LEN = p-> srh_len;
    if(SRH_LEN > MAX_SRH_LEN){
        bpf_printk("SRH_LEN > MAX_SRH_LEN -> dropping");    
        return XDP_DROP;
    }
    if((void *)((char *)p->srh + SRH_LEN) > end)
        return XDP_DROP;
    
    p->outer_len = sizeof(struct ipv6hdr) + SRH_LEN;
    __u32 SRV6_LEN = p->outer_len;
    if((void *)((char *)p->ip6 + SRV6_LEN) > end){
        bpf_printk("ipv6 header + SRV6 header exceeds packet boundaries -> dropping");
        return XDP_DROP;
    }

    if((void *)((char *)p->srh->segments + (SRH_LEN - 8)) > end){
        bpf_printk("segment list is too long");
        return XDP_DROP;
    }
    
    // determine inner proto for ethernet header in encap, since it might change in the VNF
    bpf_printk("Decap: Parsed SRH --> SRH_LEN = %u, SRV6_LEN = %u", SRH_LEN, SRV6_LEN);
    /*
    UPDATE THE HEADER IN PACKET
    */
   // proof that segmentsLeft is in packet range
    if((void *)(p->srh->segments) > end)
        return XDP_DROP;
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
    SELECT THE SERVICE CHAIN SLOT/LANE
    */
    // just choose first slot for now
    //__u32 slot = SLOT;
    (*clock)++; // ensure clock is always bigger than 0

    __u32 seg_len = (SRH_LEN - 8)/ sizeof(struct in6addr);
    __u32 seg_bytes = seg_len * sizeof(struct in6_addr);
    if(seg_len == 0 || seg_len > MAX_SEGS)
        return XDP_DROP;

    __s32 lane = assign_lane(p->srh->segments, seg_len, clock);
    if(lane < 0){
        bpf_printk("Lane assignemnt is negative.");
        return XDP_DROP;
    }
    if(lane >= N){
        bpf_printk("assigned lane is bigger than #lanes");
        return XDP_DROP;
    }
    /*
    READ CACHED ENTRY
    */
    // |-------ZERO-INITIALIZED-BY-GO-PROGRAM-------|
    struct cached_outer *cached = bpf_map_lookup_elem(&srh_table, &lane);
    if (!cached) 
        return XDP_DROP;
    
    if((void *)cached->bytes + 2 <= end)
        bpf_printk("Looked Up cached header successfully: %02x, %02x", cached->bytes[0], cached->bytes[1]);

    /*
    UPDATE CACHE: COPY IPv6 (outer) + SRH TO CACHE BUFFER
    */
    if(SRV6_LEN > MAX_CACHED_HDR)
        return XDP_DROP;
    if(sizeof(cached->bytes) < SRV6_LEN)
        return XDP_DROP;
    if((void *)((char *)p->ip6 + SRV6_LEN) > end)
        return XDP_DROP;

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
    __u32 src_key = lane;
    __u32 dst_key = N + lane;
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
    __u32 *link_index = bpf_map_lookup_elem(&link_index_table, &lane);
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