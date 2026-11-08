#include <core.p4>
#include <v1model.p4>

#define MAX_SEGMENTS 8

const bit<16> IPV6_ETHERTYPE = 0x86DD;
const bit<8> IPV6_NEXT_HEADER_ROUTING = 43;
const bit<8> IPV4_NEXT_HEADER = 4;   // IPv4-in-IPv6
const bit<8> IPV6_NEXT_HEADER = 41;  // IPv6-in-IPv6

header ethernet_h {
  bit<48> dstAddr;
  bit<48> srcAddr;
  bit<16> etherType;
}

header ipv4_h {
  bit<4>  version;
  bit<4>  ihl;
  bit<8>  diffserv;
  bit<16> total_len;
  bit<16> identification;
  bit<3>  flags;
  bit<13> frag_offset;
  bit<8>  ttl;
  bit<8>  protocol;
  bit<16> hdr_checksum;
  bit<32> src_addr;
  bit<32> dst_addr;
}

header ipv6_h {
  bit<4>   version;
  bit<8>   traffic_class;
  bit<20>  flow_label;
  bit<16>  payload_len;
  bit<8>   next_hdr;
  bit<8>   hop_limit;
  bit<128> src_addr;
  bit<128> dst_addr;
}

header srv6_h {
  bit<8>  next_hdr;
  bit<8>  hdr_ext_len;
  bit<8>  routing_type;
  bit<8>  segments_left;
  bit<8>  last_entry;
  bit<8>  flags;
  bit<16> tag;
}

header segment_h {
  bit<128> segment;
}

struct metadata_t {
  bool allowed;
}

struct headers {
  ethernet_h ethernet;
  ipv6_h outer_ipv6;
  srv6_h srh;
  segment_h[MAX_SEGMENTS] segment_list;
  ipv4_h inner_ipv4;
  ipv6_h inner_ipv6;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata_t meta,
                inout standard_metadata_t stdmeta) {
  state start {
    packet.extract(hdr.ethernet);
    transition select(hdr.ethernet.etherType) {
        IPV6_ETHERTYPE: parse_outer_ipv6;
        default: accept;
    }
  }

  state parse_outer_ipv6 {
    packet.extract(hdr.outer_ipv6);
    transition select(hdr.outer_ipv6.next_hdr) {
        IPV6_NEXT_HEADER_ROUTING: parse_srh;
        default: accept;
    }
  }

  state parse_srh {
    packet.extract(hdr.srh);
    // last_entry is the index of the last segment, so it must fit the stack
    transition select(hdr.srh.last_entry < MAX_SEGMENTS) {
        true: parse_srh_segments;
        false: reject;
    }
  }

  state parse_srh_segments {
    packet.extract(hdr.segment_list.next);
    transition select(hdr.segment_list.lastIndex < (bit<32>)hdr.srh.last_entry) {
        true: parse_srh_segments; // loop until all segments are extracted
        false: parse_inner_header;
    }
  }

  state parse_inner_header {
    transition select(hdr.srh.next_hdr) {
      IPV4_NEXT_HEADER: parse_inner_ipv4;
      IPV6_NEXT_HEADER: parse_inner_ipv6;
      default: accept;
    }
  }

  state parse_inner_ipv4 {
    packet.extract(hdr.inner_ipv4);
    transition accept;
  }

  state parse_inner_ipv6 {
    packet.extract(hdr.inner_ipv6);
    transition accept;
  }
}

control MyVerifyChecksum(inout headers hdr, inout metadata_t meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t stdmeta){

    counter(1, CounterType.packets_and_bytes) forward_counter;

    action srv6_forward() {
        forward_counter.count(0);

        if (hdr.srh.segments_left > 0 &&
            hdr.srh.segments_left <= hdr.srh.last_entry + 1) {
            hdr.srh.segments_left = hdr.srh.segments_left - 1;
            hdr.outer_ipv6.dst_addr = hdr.segment_list[hdr.srh.segments_left].segment;

            // Swap MACs and send the packet back out the port it came in on
            bit<48> original_src = hdr.ethernet.srcAddr;
            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            hdr.ethernet.dstAddr = original_src;
            stdmeta.egress_spec = stdmeta.ingress_port;
        } else {
            mark_to_drop(stdmeta);
        }
    }

    table forward_table {
        actions = {
            srv6_forward;
        }
        default_action = srv6_forward();
    }

    apply {
        if (hdr.outer_ipv6.isValid() &&
            hdr.srh.isValid() &&
            hdr.segment_list[0].isValid()) {
            forward_table.apply();
        } else {
            // Not an SRv6 packet we handle. Without this egress_spec stays 0.
            mark_to_drop(stdmeta);
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t stdmeta) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata_t meta) {
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.outer_ipv6);
        packet.emit(hdr.srh);
        packet.emit(hdr.segment_list);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_ipv6);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;