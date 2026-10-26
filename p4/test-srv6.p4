#include <doca_model.p4>
#include <doca_headers.p4>
#include <doca_externs.p4>
#include <doca_parser.p4>

header segment_t {
	bit<128> segment;
}

header srh_base_t {
	bit<8> next_header;
	bit<8> hdr_ext_len;
	bit<8> routing_type;
	bit<8> segments_left;
	bit<8> last_entry;
	bit<8> flags;
	bit<16> tag;
}

struct custom_headers {
	NV_FIXED_HEADERS
	srh_base_t srh;
	//segment_t sid_r0;
	segment_t sid_r1;
	segment_t sid_r2;
	segment_t sid_r3;
	segment_t sid_r4;
	segment_t sid_r5;
	segment_t sid_r6;
	segment_t sid_r7;
	segment_t sid_r8;
	//segment_t sid9;
	//segment_t sid10;
	//segment_t sid11;
	//segment_t sid12;
	//segment_t sid13;
	//segment_t sid14;
	//segment_t sid15;
}


parser packet_parser(packet_in packet, out custom_headers headers) {
    NV_FIXED_PARSER(packet, headers)
 
    @nv_transition_from("nv_parse_ipv4, nv_parse_ipv6", 0x2b)
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
    state parse_sid_r1 { packet.extract(headers.sid_r1); transition parse_next_header; }
 
 
    state parse_next_header {
       transition select(packet.lookahead<bit<4>>()) {
            4: nv_parse_inner_ipv4;
            6: nv_parse_inner_ipv6;
            default: accept;
        }
    }
}

control forward_control(
    inout custom_headers headers,
    in nv_standard_metadata_t std_meta,
    inout nv_empty_metadata_t user_meta,
    inout nv_empty_metadata_t pkt_out_meta
){
    action drop(){
        nv_drop();
    }

    action forward(bit<32> port){
        nv_send_to_port(port);
    }

    table forward_table {
        key = { headers.ipv4.dst_addr: exact; }

        actions = {
            drop;
            forward;
        }

        default_action = forward(2);
        const entries = {
            (32w0x0A000001) : drop();
            (32w0x0A000002) : forward(2);
        }
    }

    /*table drop_table {
        key = {}
        actions = {
            drop;
        }

        default_action = drop();
    }*/

    apply {
        if(headers.inner_ipv4.isValid()){
            forward_table.apply();
        }
    }
}

NvDocaPipeline(
    packet_parser(),
    forward_control()
) main;
 