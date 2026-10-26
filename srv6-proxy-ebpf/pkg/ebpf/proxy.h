#ifndef N
#error "Compile with -DN=<number of service chains>"
#endif

#ifndef SLOT
#define SLOT 0
#endif

#define MAX_SEGLIST_LEN 2048 // 256 (8-bit hdrextLen field) 8-byte blocks -> excluding the first 8 bytes: only segs and tlvs!
#define RH_SIZE 8
#define MAX_SRH_LEN 2048 + RH_SIZE// 256 (8-bit hdrextLen field) 8-byte blocks + the first 8 octets
#define MAX_CACHED_HDR (sizeof(struct ipv6hdr) + MAX_SRH_LEN) // account for routing header
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