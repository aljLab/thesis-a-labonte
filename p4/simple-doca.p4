#include <doca_model.p4>
#include <doca_headers.p4>
#include <doca_externs.p4>
#include <doca_parser.p4>

control forward(
    inout nv_headers_t hdr,
    in nv_standard_metadata_t std_meta,
    inout nv_empty_metadata_t usr_meta,
    out nv_empty_metadata_t pkt_out_meta
){
    action drop(){
        nv_drop();
    }

    action forward(bit<32> port){
        nv_send_to_port(port);
    }

    table forward {
        key = { hdr.ipv4.dst_addr: exact; }

        actions = {
            drop;
            forward;
        }

        default_action = drop();
        const entries = {
            (32w0x0A000001) : drop();
            (32w0x0A000002) : forward(2);
        }
    }

    apply {
        if(hdr.ipv4.isValid()){
            forward.apply();
        }
    }
}