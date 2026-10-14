#include <doca_model.p4>
#include <doca_headers.p4>
#include <doca_externs.p4>
#include <doca_parser.p4>


control reflector(
    inout nv_headers_t headers,
    in nv_standard_metadata_t std_meta,
    inout nv_empty_metadata_t user_meta,
    inout nv_empty_metadata_t pkt_out_meta
) {
    action drop() {
        nv_drop();
    }

    action forward(bit<32> port) {
        nv_send_to_port(port);
    }

    table forward_table {
        key = {
            headers.ipv4.dst_addr: exact;
        }
        actions = {
            drop;
            forward;
            NoAction;
        }
        default_action = forward(2);
        const entries = {
            (32w0x0A000001) : drop();
            (32w0x0A000002) : forward(2);
        }
    }
    apply {
        forward_table.apply();
    }
}

NvDocaPipeline(
    nv_fixed_parser(),
    reflector()
) main;