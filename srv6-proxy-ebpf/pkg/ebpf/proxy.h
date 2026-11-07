#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/*
CONSTANTS
*/

#ifndef N
#error "Compile with -DN=<number of service chains>"
#endif

#define MAX_LANES 8
#define MAX_SEGMENTS 128
#define MAX_COMP_SEGMENTS 128
#define MAX_SEGLIST_BYTES MAX_SEGMENTS*16 // 256 (8-bit hdrextLen field) 8-byte blocks -> excluding the first 8 bytes: only segs and tlvs!
#define RH_SIZE 8
#define MAX_SRH_LEN MAX_SEGLIST_BYTES + RH_SIZE// 256 (8-bit hdrextLen field) 8-byte blocks + the first 8 octets
#define MAX_CACHED_HDR (sizeof(struct ipv6hdr) + MAX_SRH_LEN) // account for routing header

#define MAX_L3_HDR_BYTES 40 // max(max_len(ipv6_hdr), max_len(ipv4_hdr))
#define MAX_L4_HDR_BYTES 20 // max(max_len(udp_hdr), max_len(tcp_hdr))
#define MAX_SRH_KEY_LEN MAX_L3_HDR_BYTES + MAX_L4_HDR_BYTES
#define MAX_SRH_CACHE_ENTRIES 128
#define MAX_L3_L4_COMBINATIONS 4 // #supported_l3_protos * #supported_l4_protos
#define MAX_FIXED_HDR_LEN_GLOBAL 40 // max(MAX_L3_HDR_BYTES, MAX_L4_HDR_BYTES)
#define L3_KEY_SIZE MAX_L3_HDR_BYTES
#define L4_KEY_SIZE MAX_L4_HDR_BYTES

/*
STRUCTS
*/

struct cached_outer {
    struct bpf_spin_lock lock;
    __u16 len;
    __u16 pad;
    __u8 bytes[MAX_CACHED_HDR];
};

struct cached_outer_mock {
    __u8 bytes[sizeof(struct cached_outer)];
};

struct mac_entry {
    __u8 addr[6];
    __u8 pad[2];
};

struct sfc_t {
    struct bpf_spin_lock lock;
    __u64 last_seen; // monotonic clock value of last encounter of traffic from this service chain
    struct in6_addr segments[MAX_SEGMENTS];
    __u32 n_segs;
};

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
    __u32 n_segs;
};

struct pkt_tcp_ip4 {
    struct ethhdr *eth;
    struct ipv6hdr *ip6;
    struct ipv6_sr_hdr *srh;
    struct iphdr *inner_ip4;
    struct tcphdr *tcp;
    __u32 srh_len;
};

struct pkt_tcp_ip6 {
    struct ethhdr *eth;
    struct ipv6hdr *ip6;
    struct ipv6_sr_hdr *srh;
    struct ipv6hdr *inner_ip6;
    struct tcphdr *tcp;
    __u32 srh_len;
};

struct pkt_udp_ip4 {
    struct ethhdr *eth;
    struct ipv6hdr *ip6;
    struct ipv6_sr_hdr *srh;
    struct iphdr *inner_ip4;
    struct udphdr *udp;
    __u32 srh_len;
};

struct pkt_udp_ip6 {
    struct ethhdr *eth;
    struct ipv6hdr *ip6;
    struct ipv6_sr_hdr *srh;
    struct ipv6hdr *inner_ip6;
    struct udphdr *udp;
    __u32 srh_len;
};

struct lane_meta {
    __u32 lane;
} __attribute__((aligned(4)));

struct proxy_meta {
    __u32 lane;
} __attribute__((aligned(4)));

struct srh_key {
    __u8 l3[L3_KEY_SIZE];
    __u8 l4[L4_KEY_SIZE];
};

struct l3_mask_t {
    __u8 bytes[MAX_L3_HDR_BYTES];
};
struct l4_mask_t {
    __u8 bytes[MAX_L4_HDR_BYTES];
};

struct inner_l3_hdr {
    struct ipv6hdr *ip6;
    struct iphdr *ip4;
};

struct key_meta {
    struct srh_key key;
};