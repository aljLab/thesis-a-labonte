/*
* srv6_srh_dyn8.p4
*
* DPL (DOCA Pipeline Language) program for BlueField-3 that parses:
*
*   Ethernet -> IPv6 -> SRH (Routing Header, type 4) -> 1..8 SIDs
*
* Compile:
*   dpl nvp4c --target doca-bf3 srv6_srh_dyn8.p4
*
* Hardware note:
*   Custom headers are parsed by the BlueField-3 flex parser, which has a
*   small pool of registers. The active SID is read from the IPv6
*   destination address (SRv6 copies it there), which the fixed parser
*   already extracts, so the control block does not read the SID headers.
*   Reading them in the control can fail with
*   "Parser register allocation failed".
*
* DPL parser restrictions this follows:
*   - No header stacks, no varbit, no loops in the parse graph.
*   - Each state extracts exactly one fixed-size header.
*   - select() may use only one field of the header extracted in that state.
*
* SID chain: the SRH state branches on Last Entry (number of SIDs - 1)
* and jumps into a countdown chain at the right depth:
*
*   last_entry = 7 -> sid_r8 -> sid_r7 -> ... -> sid_r1 -> accept  (8 SIDs)
*   last_entry = 2 ->                   sid_r3 -> sid_r2 -> sid_r1  (3 SIDs)
*   last_entry = 0 ->                                       sid_r1  (1 SID)
*
* Instances are named by distance from the END of the segment list.
* With n = last_entry + 1 SIDs:
*
*     sid_rK  holds  Segment List[n - K]
*     sid_r1   = Segment List[last_entry]  (first SID visited)
*     sid_r(n) = Segment List[0]           (final destination SID)
*
* SRHs with more than 8 SIDs are not parsed past the SRH and are dropped.
*/
 
#include <doca_model.p4>
#include <doca_headers.p4>
#include <doca_externs.p4>
#include <doca_parser.p4>
 
#define IPPROTO_ROUTING   0x2B   /* IPv6 next header: Routing Header */
#define SRH_ROUTING_TYPE  4      /* Segment Routing Header           */
 
/* ------------------------------------------------------------------ */
/* Headers                                                             */
/* ------------------------------------------------------------------ */
 
header srh_h {
    bit<8>  next_hdr;
    bit<8>  hdr_ext_len;
    bit<8>  routing_type;
    bit<8>  segments_left;
    bit<8>  last_entry;
    bit<8>  flags;
    bit<16> tag;
}
 
header sid_h {
    bit<128> sid;
}
 
struct headers_t {
    NV_FIXED_HEADERS
    srh_h srh;
    sid_h sid_r8;
    sid_h sid_r7;
    sid_h sid_r6;
    sid_h sid_r5;
    sid_h sid_r4;
    sid_h sid_r3;
    sid_h sid_r2;
    sid_h sid_r1;   /* always the last SID on the wire = first SID visited */
}
 
/* The two counters are 32-bit because the target only supports ordered
* comparisons (<, <=, >, >=) on 32-bit values. */
struct metadata_t {
    bit<32> num_sids;    /* last_entry + 1, or 0 if more than 8 SIDs */
    bit<32> seg_left;    /* srh.segments_left widened to 32 bits     */
}
 
/* ------------------------------------------------------------------ */
/* Parser                                                              */
/* ------------------------------------------------------------------ */
 
parser packet_parser(packet_in packet, out headers_t headers) {
    NV_FIXED_PARSER(packet, headers)
 
    /* IPv6 next header == 43 (Routing); overrides the fixed IPv6-Route
     * transition. The target keeps one protocol transition table shared
     * by IPv4 and IPv6, so a custom L3 -> next-protocol transition must be
     * declared from both. IPv4 protocol 43 packets therefore also land
     * here; the control block ignores SRH unless the packet is IPv6. */
    @nv_transition_from("nv_parse_ipv6, nv_parse_ipv4", IPPROTO_ROUTING)
    state parse_srh {
        packet.extract(headers.srh);
        /* Enter the countdown chain at depth (last_entry + 1).
         * last_entry > 7 (more than 8 SIDs) stops parsing here. */
        transition select(headers.srh.last_entry) {
            0: parse_sid_r1;
            1: parse_sid_r2;
            2: parse_sid_r3;
            3: parse_sid_r4;
            4: parse_sid_r5;
            5: parse_sid_r6;
            6: parse_sid_r7;
            7: parse_sid_r8;
     default: accept;
        }
    }
 
    state parse_sid_r8 { packet.extract(headers.sid_r8); transition parse_sid_r7; }
    state parse_sid_r7 { packet.extract(headers.sid_r7); transition parse_sid_r6; }
    state parse_sid_r6 { packet.extract(headers.sid_r6); transition parse_sid_r5; }
    state parse_sid_r5 { packet.extract(headers.sid_r5); transition parse_sid_r4; }
    state parse_sid_r4 { packet.extract(headers.sid_r4); transition parse_sid_r3; }
    state parse_sid_r3 { packet.extract(headers.sid_r3); transition parse_sid_r2; }
    state parse_sid_r2 { packet.extract(headers.sid_r2); transition parse_sid_r1; }
 
 
    state parse_sid_r1 {
        packet.extract(headers.sid_r1,);
        /* sid_h has no next-header field to select on, so parsing ends. */
        transition accept;
    }
}
 
/* ------------------------------------------------------------------ */
/* Control                                                             */
/* ------------------------------------------------------------------ */
 
control srv6_pipeline(
    inout headers_t              headers,
    in    nv_standard_metadata_t std_meta,
    inout metadata_t             user_meta,
    inout nv_empty_metadata_t    pkt_out_meta
) {
    apply {
    }
}
 
/* ------------------------------------------------------------------ */
/* Package                                                             */
/* ------------------------------------------------------------------ */
 
NvDocaPipeline(
    packet_parser(),
    srv6_pipeline()
) main;
 