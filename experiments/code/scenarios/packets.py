from scapy.all import Ether, Raw, IPv6, IP, IPv6ExtHdrSegmentRouting, UDP, AsyncSniffer, sendp

BOGUS_MAC = "02:00:00:00:00:02"
src_mac = dst_mac = BOGUS_MAC
SEGMENT_LIST_SFC1 = ["2001:db8:3::1","2001:db8:2::1"]
SEGMENT_LIST_SFC2 = ["2001:db8:3::1","2001:db8:2::1", "2001:db8:4::1"]
SEGMENT_LIST_SFC3 = ["2001:db8:5::1","2001:db8:6::1", "2001:db8:4::1"]
SEGMENT_LIST_SFC4 = ["2001:db8:5::1","2001:db8:6::1", "2001:db8:8::1"]
SEGMENT_LIST_SFC5 = ["2001:db8:9::1", "2001:db8:9::2"]
SEGMENT_LIST_SFC6 = ["2001:db8:3::1","2001:db8:2::1"]
SEGMENT_LIST_SFC7 = ["2001:db8:3::1","2001:db8:2::1", "2001:db8:4::2"]
SEGMENT_LIST_SFC8 = ["2001:db8:5::1","2001:db8:6::1", "2001:db8:4::2"]
SEGMENT_LIST_SFC9 = ["2001:db8:5::1","2001:db8:6::1", "2001:db8:8::2"]
SEGMENT_LIST_SFC10 = ["2001:db8:9::1", "2001:db8:9::2"]

payload = ""

pkt_ipv4 = (
    Ether(src=src_mac, dst=dst_mac) /
    IPv6(src="fd00::1", dst="fd00::2") /
    UDP(sport=12345, dport=12346) /
    Raw(load=payload)
)

pkt_srv6_ip4_sfc1 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC1, segleft=len(SEGMENT_LIST_SFC1)-1, lastentry=len(SEGMENT_LIST_SFC1)-1) / 
    IP(src="10.0.0.1", dst="10.0.0.2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_srv6_ip4_sfc2 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC2, segleft=len(SEGMENT_LIST_SFC2)-1, lastentry=len(SEGMENT_LIST_SFC2)-1) / 
    IP(src="10.0.0.1", dst="10.0.0.2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_srv6_ip4_sfc3 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC3, segleft=len(SEGMENT_LIST_SFC3)-1, lastentry=len(SEGMENT_LIST_SFC3)-1) / 
    IP(src="10.0.0.1", dst="10.0.0.2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_srv6_ip4_sfc4 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC4, segleft=len(SEGMENT_LIST_SFC4)-1, lastentry=len(SEGMENT_LIST_SFC4)-1) / 
    IP(src="10.0.0.1", dst="10.0.0.2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_srv6_ip4_sfc5 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC5, segleft=len(SEGMENT_LIST_SFC5)-1, lastentry=len(SEGMENT_LIST_SFC5)-1) / 
    IP(src="10.0.0.1", dst="10.0.0.2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_srv6_ip4_sfc6 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC6, segleft=len(SEGMENT_LIST_SFC6)-1, lastentry=len(SEGMENT_LIST_SFC6)-1) / 
    IP(src="10.0.0.1", dst="10.0.0.2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_srv6_ip4_sfc7 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC7, segleft=len(SEGMENT_LIST_SFC7)-1, lastentry=len(SEGMENT_LIST_SFC7)-1) / 
    IP(src="10.0.0.1", dst="10.0.0.2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_srv6_ip4_sfc8 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC8, segleft=len(SEGMENT_LIST_SFC8)-1, lastentry=len(SEGMENT_LIST_SFC8)-1) / 
    IP(src="10.0.0.1", dst="10.0.0.2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_srv6_ip4_sfc9 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC9, segleft=len(SEGMENT_LIST_SFC9)-1, lastentry=len(SEGMENT_LIST_SFC9)-1) / 
    IP(src="10.0.0.1", dst="10.0.0.2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_srv6_ip4_sfc10 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC10, segleft=len(SEGMENT_LIST_SFC10)-1, lastentry=len(SEGMENT_LIST_SFC10)-1) / 
    IP(src="10.0.0.1", dst="10.0.0.2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)

pkt_srv6_ip6_sfc1 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC1, segleft=len(SEGMENT_LIST_SFC1)-1, lastentry=len(SEGMENT_LIST_SFC1)-1) / 
    IPv6(src="fd00::1", dst="fd00::2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_srv6_ip6_sfc2 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC2, segleft=len(SEGMENT_LIST_SFC2)-1, lastentry=len(SEGMENT_LIST_SFC2)-1) / 
    IPv6(src="fd00::1", dst="fd00::2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_srv6_ip6_sfc3 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC3, segleft=len(SEGMENT_LIST_SFC3)-1, lastentry=len(SEGMENT_LIST_SFC3)-1) / 
    IPv6(src="fd00::1", dst="fd00::2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_srv6_ip6_sfc4 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC4, segleft=len(SEGMENT_LIST_SFC4)-1, lastentry=len(SEGMENT_LIST_SFC4)-1) / 
    IPv6(src="fd00::1", dst="fd00::2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_srv6_ip6_sfc5 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC5, segleft=len(SEGMENT_LIST_SFC5)-1, lastentry=len(SEGMENT_LIST_SFC5)-1) / 
    IPv6(src="fd00::1", dst="fd00::2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_srv6_ip6_sfc6 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC6, segleft=len(SEGMENT_LIST_SFC6)-1, lastentry=len(SEGMENT_LIST_SFC6)-1) / 
    IPv6(src="fd00::1", dst="fd00::2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_srv6_ip6_sfc7 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC7, segleft=len(SEGMENT_LIST_SFC7)-1, lastentry=len(SEGMENT_LIST_SFC7)-1) / 
    IPv6(src="fd00::1", dst="fd00::2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_srv6_ip6_sfc8 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC8, segleft=len(SEGMENT_LIST_SFC8)-1, lastentry=len(SEGMENT_LIST_SFC8)-1) / 
    IPv6(src="fd00::1", dst="fd00::2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_srv6_ip6_sfc9 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC9, segleft=len(SEGMENT_LIST_SFC9)-1, lastentry=len(SEGMENT_LIST_SFC9)-1) / 
    IPv6(src="fd00::1", dst="fd00::2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_srv6_ip6_sfc10 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC10, segleft=len(SEGMENT_LIST_SFC10)-1, lastentry=len(SEGMENT_LIST_SFC10)-1) / 
    IPv6(src="fd00::1", dst="fd00::2") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)

# varied IPv4 subnets for correlation-based proxy, requires the proxy to match on e.g. 0xffffff00 (/24) on dst and src

pkt_ip4_src_dst1 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC1, segleft=len(SEGMENT_LIST_SFC1)-1, lastentry=len(SEGMENT_LIST_SFC1)-1) / 
    IP(src="10.1.1.1", dst="10.1.2.1") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_ip4_src_dst2 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC3, segleft=len(SEGMENT_LIST_SFC3)-1, lastentry=len(SEGMENT_LIST_SFC3)-1) / 
    IP(src="10.2.1.1", dst="10.2.2.1") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_ip4_src_dst3 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC5, segleft=len(SEGMENT_LIST_SFC5)-1, lastentry=len(SEGMENT_LIST_SFC5)-1) / 
    IP(src="10.3.1.1", dst="10.3.2.1") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_ip4_src_dst4 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC6, segleft=len(SEGMENT_LIST_SFC6)-1, lastentry=len(SEGMENT_LIST_SFC6)-1) / 
    IP(src="10.4.1.1", dst="10.4.2.1") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_ip4_src_dst5 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC7, segleft=len(SEGMENT_LIST_SFC7)-1, lastentry=len(SEGMENT_LIST_SFC7)-1) / 
    IP(src="10.5.1.1", dst="10.5.2.1") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_ip4_src_dst6 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC7, segleft=len(SEGMENT_LIST_SFC7)-1, lastentry=len(SEGMENT_LIST_SFC7)-1) / 
    IP(src="10.6.1.1", dst="10.6.2.1") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_ip4_src_dst7 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC8, segleft=len(SEGMENT_LIST_SFC8)-1, lastentry=len(SEGMENT_LIST_SFC8)-1) / 
    IP(src="10.7.1.1", dst="10.7.2.1") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_ip4_src_dst8 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC9, segleft=len(SEGMENT_LIST_SFC9)-1, lastentry=len(SEGMENT_LIST_SFC9)-1) / 
    IP(src="10.8.1.1", dst="10.8.2.1") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_ip4_src_dst9 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC9, segleft=len(SEGMENT_LIST_SFC9)-1, lastentry=len(SEGMENT_LIST_SFC9)-1) / 
    IP(src="10.9.1.1", dst="10.9.2.1") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)
pkt_ip4_src_dst10 = (
    Ether(src=BOGUS_MAC.lower(), dst=dst_mac) / 
    IPv6(src="2001:db8:1::1", dst="2001:db8:2::1") / 
    IPv6ExtHdrSegmentRouting(addresses=SEGMENT_LIST_SFC10, segleft=len(SEGMENT_LIST_SFC10)-1, lastentry=len(SEGMENT_LIST_SFC10)-1) / 
    IP(src="10.10.1.1", dst="10.10.2.1") / 
    UDP(sport=12345, dport=12346) / 
    Raw(load=payload)
)

scenario_lib = {
    "default": [pkt_srv6_ip6_sfc1],
    "ipv4-only": [pkt_ipv4],
    "srv6-ipv4-1": [pkt_srv6_ip4_sfc1],
    "srv6-ipv4-2": [pkt_srv6_ip4_sfc1, pkt_srv6_ip4_sfc2],
    "srv6-ipv4-5": [pkt_srv6_ip4_sfc1, pkt_srv6_ip4_sfc2, pkt_srv6_ip4_sfc3, pkt_srv6_ip4_sfc4, pkt_srv6_ip4_sfc5],
    "srv6-ipv4-10": [pkt_srv6_ip4_sfc1, pkt_srv6_ip4_sfc2, pkt_srv6_ip4_sfc3, pkt_srv6_ip4_sfc4, pkt_srv6_ip4_sfc5, pkt_srv6_ip4_sfc6, pkt_srv6_ip4_sfc7, pkt_srv6_ip4_sfc8, pkt_srv6_ip4_sfc9, pkt_srv6_ip4_sfc10],
    "srv6-ipv6-1": [pkt_srv6_ip6_sfc1],
    "srv6-ipv6-2": [pkt_srv6_ip6_sfc1, pkt_srv6_ip6_sfc2],
    "srv6-ipv6-5": [pkt_srv6_ip6_sfc1, pkt_srv6_ip6_sfc2, pkt_srv6_ip6_sfc3, pkt_srv6_ip6_sfc4, pkt_srv6_ip6_sfc5],
    "srv6-ipv6-10": [pkt_srv6_ip6_sfc1, pkt_srv6_ip6_sfc2, pkt_srv6_ip6_sfc3, pkt_srv6_ip6_sfc4, pkt_srv6_ip6_sfc5, pkt_srv6_ip6_sfc6, pkt_srv6_ip6_sfc7, pkt_srv6_ip6_sfc8, pkt_srv6_ip6_sfc9, pkt_srv6_ip6_sfc10],
    "ipv4-src-dst-1": [pkt_ip4_src_dst1],
    "ipv4-src-dst-2": [pkt_ip4_src_dst1, pkt_ip4_src_dst2],
    "ipv4-src-dst-5": [pkt_ip4_src_dst1, pkt_ip4_src_dst2, pkt_ip4_src_dst3, pkt_ip4_src_dst4, pkt_ip4_src_dst5],
    "ipv4-src-dst-10": [pkt_ip4_src_dst1, pkt_ip4_src_dst2, pkt_ip4_src_dst3, pkt_ip4_src_dst4, pkt_ip4_src_dst5, pkt_ip4_src_dst6, pkt_ip4_src_dst7, pkt_ip4_src_dst8, pkt_ip4_src_dst9, pkt_ip4_src_dst10]
}