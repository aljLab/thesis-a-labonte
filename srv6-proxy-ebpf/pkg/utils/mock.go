package utils

import(
	"fmt"
)

var MockTcpImmutableHdrFields = []ImmutableHeaderField{
	{
		Proto: PROTO_TCP,
		Field: TCP_DST_PORT,
		Match: MatchType{
			Type: EXACT_MATCH,
		},
	},
	{
		Proto: PROTO_TCP,
		Field: TCP_SRC_PORT,
		Match: MatchType{
			Type: BITMASK_MATCH,
			BitMask: "0xf0f0",
		},
	},
}

var MockUdpImmutableHdrFields = []ImmutableHeaderField{
	{
		Proto: PROTO_UDP,
		Field: UDP_DST_PORT,
		Match: MatchType{
			Type: EXACT_MATCH,
		},
	},
	{
		Proto: PROTO_UDP,
		Field: UDP_SRC_PORT,
		Match: MatchType{
			Type: EXACT_MATCH,
		},
	},
}

var MockIPv4ImmutableHdrFields = []ImmutableHeaderField{
	{
		Proto: PROTO_IPv4,
		Field: IPv4_DST_ADDR,
		Match: MatchType{
			Type: BITMASK_MATCH,
			BitMask: "0xffffff00",
		},
	},
	{
		Proto: PROTO_IPv4,
		Field: IPv4_SRC_ADDR,
		Match: MatchType{
			Type: BITMASK_MATCH,
			BitMask: "0xffffff00",
		},
	},
	{
		Proto: PROTO_IPv4,
		Field: IPv4_ECN,
		Match: MatchType{
			Type: BITMASK_MATCH,
			BitMask: "0xff",
		},
	},
}

var MockIPv6ImmutableHdrFields = []ImmutableHeaderField{
	{
		Proto: PROTO_IPv6,
		Field: IPv6_SRC_ADDR,
		Match: MatchType{
			Type: BITMASK_MATCH,
			BitMask: "0xffffffffffff00000000ffffffffffff",
		},
	},
	{
		Proto: PROTO_IPv6,
		Field: IPv6_TRAFFIC_CLASS,
		Match: MatchType{
			Type: EXACT_MATCH,
		},
	},
	{
		Proto: PROTO_IPv6,
		Field: IPv6_FLOW_LABEL,
		Match: MatchType{
			Type: EXACT_MATCH,
		},
	},
}

func getMockMasks(){
	maskv4, err := GetKeyMaskForProto(MockIPv4ImmutableHdrFields); if err != nil {
        fmt.Printf("err ipv4 fields: %s\n", err)
    }

    if maskv4 != nil {
        fmt.Printf("Mask V4: %x\n", maskv4)
    }
    maskv6, err := GetKeyMaskForProto(MockIPv6ImmutableHdrFields); if err != nil {
        fmt.Printf("err ipv6 fields: %s\n", err)
    }

    if maskv6 != nil {
        fmt.Printf("Mask V6: %x\n", maskv6)
    }
    maskudp, err := GetKeyMaskForProto(MockUdpImmutableHdrFields); if err != nil {
        fmt.Printf("err udp fields: %s\n", err)
    }

    if maskudp != nil {
        fmt.Printf("Mask udp: %x\n", maskudp)
    }
    masktcp, err := GetKeyMaskForProto(MockTcpImmutableHdrFields); if err != nil {
        fmt.Printf("err tcp fields: %s\n", err)
    }

    if masktcp != nil {
        fmt.Printf("Mask tcp: %x\n", masktcp)
    }

}