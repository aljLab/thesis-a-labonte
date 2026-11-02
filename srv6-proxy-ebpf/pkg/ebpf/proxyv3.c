#include "proxy.h"

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

static __always_inline
int parse_packet(struct parsed_srh *p, void *start, void *end)
{

    bpf_printk("starting to parse headers...");

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
    // sanity check hdr_ext_len and prove parsing hdr_ext_len bytes after p->srh + 8 is not going across packet boundaries
    /* if(hdr_ext_len > (__u16)(MAX_SEGLIST_LEN / 8)){
        bpf_printk("hdr len %u does not check out -> dropping", hdr_ext_len);    
        return XDP_DROP;
    } */
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
int update_srh(struct parsed_srh *p, void *end)
{   
    if(p->srh_len > MAX_SRH_LEN)
        return -1;
    if((void *)((char *)p->srh + p->srh_len) > end)
        return -1;
    if((void *)((char *)p->srh + 8) > end)
        return -1;
    
    if(p->srh->segments_left < 1)
        return XDP_PASS; // pass on, seems to be last segment which we can't handle
    p->srh->segments_left--;
    __u8 index = p->srh->segments_left;

    if(index >= (p->srh_len - 8)/sizeof(struct in6_addr)) // ensure index is not bigger than the actual length of the segment list
        return -1;
    if((void *)((struct in6_addr *)p->srh->segments + index + 1) > end)
        return -1;
    
    __builtin_memcpy((void *)&(p->ip6->daddr), (void *)((struct in6_addr *)p->srh->segments + index), sizeof(p->ip6->daddr));

    bpf_printk("Decap: Updated the SRH.");
    return 0;
}

static __noinline
int assign_lane(struct in6_addr *new_segs, __u32 n_seg, __u64 *clock, __u32 *lane, void *end)
{   
    (*lane) = 0; // test
    return 0;
    __s32 oldest_lane = -1; // stores the lane to be evicted if new_segs is a new SFC
    __u64 oldest_time = 1ULL << 63; // initialize to max of allowed distance between two packets
    struct sfc_t *oldest_sfc = NULL;

    // proof length of new_segs
    __u32 NEW_SEG_LEN = n_seg;
    if(NEW_SEG_LEN < 1 || NEW_SEG_LEN > 128)
        return -1;
    __u32 n = N;
    if(n > 16)
        n = 16;
    #pragma unroll
    for(__u32 i = 0; i < n; i++){
        __u32 key = i;
        struct sfc_t *sfc = bpf_map_lookup_elem(&sfc_lane_map, &key);

        if (!sfc)
            return -1;
        
        if(sfc->last_seen == 0){ // means lane was not assigned yet and is free
            //__builtin_memcpy((void *)sfc->segments, (void *)new_segs, NEW_SEG_LEN);
            if(n_seg > MAX_SEGLIST_LEN / 16) return -1;
            for(__u32 j = 0; j < (MAX_SEGLIST_LEN / 16); j++){
                if(j >= n_seg) break;
                if((void *)((struct in6_addr *)new_segs + j + 1) > end) return -1;
                __builtin_memcpy((void *)((struct in6_addr *)sfc->segments + j), (void *)((struct in6_addr *)new_segs + j), sizeof(struct in6_addr));
            }
            sfc->n_segs = n_seg;
            sfc->last_seen = *clock;
            *(lane) = i;
            return 0;
        }
        
        __u32 SEG_LEN = sfc->n_segs;
        
        // update eviction candidate (account for clock wrap)
        if((__s64)(sfc->last_seen - oldest_time) < 0){
            oldest_time = sfc->last_seen;
            oldest_lane = i;
            oldest_sfc = sfc; // kep reference eviction candidate
        }

        if((SEG_LEN < 1 || SEG_LEN > 128) || SEG_LEN != NEW_SEG_LEN)
            continue;

        __u8 equal = 0;
        if(sfc->n_segs == n_seg){
            for(int j = 0; j < 128; j++){
                barrier_var(j); // keep clang from changing it
                if(j >= n_seg || j >= sizeof(sfc->segments)) break;
                if((void *)((struct in6_addr *)new_segs + j + 1) > end) return -1;
                
                /* if(__builtin_memcmp((void *)((struct in6_addr*)new_segs + j), (void *)((struct in6_addr *)sfc->segments + j) , sizeof(struct in6_addr)) != 0)
                    equal = 1; */
                const __u64 *a = (const __u64 *)(new_segs + j);
                const __u64 *b = (const __u64 *)(&sfc->segments[j]);
                if (a[0] != b[0] || a[1] != b[1]) { equal = 1; break; }
            }
        } else {
            equal = 1;
        }

        if (equal == 0) {
            sfc->n_segs = n_seg;
            sfc->last_seen = *clock;
            *(lane) = i;
            return 0;
        }
    }

    if(oldest_lane < 0 || !oldest_sfc)
        return -1;
    // if no stored srh matches and no lane is free -> new sfc -> evict oldest lane
    // __builtin_memcpy((void *)oldest_sfc->segments, (void *)new_segs, NEW_SEG_LEN);
    if(n_seg > MAX_SEGLIST_LEN / 16) return -1;
    for(__u32 i = 0; i < (MAX_SEGLIST_LEN / 16); i++){
        if(i >= n_seg) break;
        if((void *)((struct in6_addr *)new_segs + i + 1) > end) return -1;
        __builtin_memcpy((void *)((struct in6_addr *)oldest_sfc->segments + i), (void *)((struct in6_addr *)new_segs + i), sizeof(struct in6_addr));
    }
    oldest_sfc->last_seen = *clock;
    oldest_sfc->n_segs = n_seg;
    *(lane) = oldest_lane;
    return 0;
}

static __always_inline
int update_cached_header(struct cached_outer *cached, char *hdr, __u32 *lane, __u32 len, void *end)
{
    if(len > MAX_CACHED_HDR)
        return -1;
    if(sizeof(cached->bytes) < len) // check capacity (not actual length)
        return -1;
    if((void *)(hdr + len) > end)
        return -1;

    bpf_spin_lock(&cached->lock);
    cached->len = len;
    // __builtin_memcpy((void *)cached->bytes, (void *)p->ip6, len);
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

    bpf_printk("Decap: updated cache: %02x, %02x", cached->bytes[0], cached->bytes[1]);

    return 0;
}
static __always_inline
int cp_ethhdr_in_front_of_inner(struct parsed_srh *p)
{
    __builtin_memcpy((void *)((char *)p->eth + p->outer_len), (void *)p->eth, sizeof(struct ethhdr));
    return 0;
}

static __always_inline
int update_eth_hdr(void *start, void *end, __u32 lane)
{
    struct ethhdr *eth = start;
    if((void *)((char *)eth + sizeof(struct ethhdr)) > end)
        return -1;

    // lookup mac addresses
    __u32 src_key = lane;
    __u32 dst_key = N + lane;
    bpf_printk("Retrieving mac's with keys: src (%u), dst (%u)", src_key, dst_key);
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
        return -1;
    }

    return 0;
}

SEC("xdp")
int decap(struct xdp_md *ctx)
{   
    bpf_printk("Entered decap program");
    __u32 clock_index = 0;
    __u64 *clock = bpf_map_lookup_elem(&clock_map, &clock_index);

    if(!clock)
        return XDP_DROP;
    
    void *start = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;

    struct parsed_srh parsed = {};
    struct parsed_srh *p = &parsed;
    // parse packet
    if(parse_packet(p, start, end) < 0)
        return XDP_DROP;
    // update SRH
    if(update_srh(p, end) < 0)
        return XDP_DROP;
    // assign lane
    __u32 lane = 0;
    (*clock)++; // ensure clock is always bigger than 0
    if(assign_lane(p->srh->segments, p->n_segs, clock, &lane, end) < 0)
        return XDP_DROP;
    // fetch cached header based on lane
    struct cached_outer *cached;
    cached = bpf_map_lookup_elem(&srh_table, &lane);
    if(!cached)
        return XDP_DROP;
    // update cached header
    if(update_cached_header(cached, (char *)p->ip6, &lane, p->outer_len, end) < 0)
        return XDP_DROP;
    // copy eth header infront of inner packet
    if(cp_ethhdr_in_front_of_inner(p))
    // get dst/src mac addresses update eth header h_proto in packet
    if(update_eth_hdr(p->eth, end, lane) < 0)
        return XDP_DROP;
    // adjust head
    if(bpf_xdp_adjust_head(ctx, p->outer_len) < 0)
        return XDP_DROP;
    // refetch pointers/reparse needed headers
    start = (void *)(long)ctx->data;
    end = (void *)(long)ctx->data_end;

    if(update_eth_hdr(start, end, lane) < 0)
        return XDP_DROP;

    bpf_printk("working in lane %u", (void *)lane);
    // fetch linkIndex of outgoing lane interface
    __u32 *link_index = bpf_map_lookup_elem(&link_index_table, &lane);
    
    if(!link_index || !*link_index){
        bpf_printk("!linkIndex");
        return XDP_DROP;
    }

    bpf_printk("redirecting packet out of %u", *link_index);
    return bpf_redirect(*link_index, 0);
}

char LICENSE[] SEC("license") = "GPL";