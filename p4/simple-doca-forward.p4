#include <doca_model.p4>
#include <doca_headers.p4>
#include <doca_externs.p4>
#include <doca_parser.p4>

control forward_control(
    inout nv_headers_t headers,
    in nv_standard_metadata_t std_meta,
    inout nv_empty_metadata_t user_meta,
    inout nv_empty_metadata_t pkt_out_meta
){
    action drop(){
        nv_drop();
    }

    action forward_to(bit<32> port){
        nv_send_to_port(port);
    }

    table forward_table {
        key = { headers.ipv6.dst_addr: exact; }

        actions = {
            drop;
            forward_to;
        }

        default_action = forward_to(2);
    }

    table drop_table {
        key = { headers.ipv6.dst_addr: exact; }

        actions = {
            forward_to;
            drop;
        }

        default_action = drop();
    }

    apply {
        if(headers.ipv6.isValid()){
            forward_table.apply();
        } else {
            drop_table.apply();
        }
    }
}

NvDocaPipeline(
    nv_fixed_parser(),
    forward_control()
) main;