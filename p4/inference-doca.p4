/* based on https://github.com/Montimage/in-network-inference-using-p4/blob/replace-iat-by-diffLen/src/bmv2/basic.p4 */

#include <doca_model.p4>
#include <doca_headers.p4>
#include <doca_externs.p4>
#include <doca_parser.p4>

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<64> feature1_t;
typedef bit<8>  inference_result_t;


struct metadata {
    //remember this info to avoid accessing from udp or tcp
    bit<16> srcPort;
    bit<16> dstPort;
    //ml features
    feature1_t feature1;

    inference_result_t ml_result;    //final classification result
}

// reg = NvMemory(1); // not available on Bluefield 3


control main_control(
    inout nv_headers_t headers,
    in nv_standard_metadata_t std_meta,
    inout metadata user_meta,
    inout nv_empty_metadata_t pkt_out_meta
) {

    action drop(){
        nv_drop();
    }

    action forward(bit<32> port) {
        nv_send_to_port(port);
    }

    action set_result(inference_result_t res){
        user_meta.ml_result = res;
    }

    table ml_code {
        key = { 
            user_meta.feature1: range; // doesnt work in doca
            headers.ipv4.totalLen: range;
        }
        actions = {
            NoAction;
            set_result;
        }
        size = 1024;
    }

    
    action get_feature1(){
        feature1_t last;
        feature1_t now;
        
        
        now = (feature1_t) hdr.ipv4.totalLen;
        //ignore the first packet as there is no IAT 
        if( last != 0 ){
            meta.feature1 = ( now + 0xFFFF - last );
        }
        //meta.feature1 = 93500;
        WRITE_REG( last_len_reg, now );
    }

    apply {

    }
}


control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* default table and its actions for packet forwarding */
    action drop() {
        mark_to_drop(standard_metadata);
    }
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    /* ml table and its actions for the final result */
    action set_result(inference_result_t val){
        meta.ml_result = val;
    }
    table ml_code{
        key = {
            meta.feature1          : range ;
            hdr.ipv4.totalLen : range ;
        }
        actions = {
            NoAction;
            set_result;
        }
       size = 1024;
    }

    //timestamp of the previous packet
    // we need only 1 element for now (without considering IAT of packets belong to a flow)
    register<feature1_t>(1) last_len_reg;
    action get_feature1(){
        feature1_t last;
        feature1_t now;
        READ_REG( last_len_reg, last );
        
        now = (feature1_t) hdr.ipv4.totalLen;
        //ignore the first packet as there is no IAT 
        if( last != 0 ){
            meta.feature1 = ( now + 0xFFFF - last );
        }
        //meta.feature1 = 93500;
        WRITE_REG( last_len_reg, now );
    }
    feature1_t last_ts;

    apply {
        if (hdr.ipv4.isValid() ) {
            //2 steps of inference:
            //  0. extract feature values
            get_feature1();
            
            //  1. match the final result
            ml_code.apply();
            
            //log_msg( "feature1: {}, len: {} => ({}, {}) => {}", {
            //    meta.feature1, hdr.ipv4.totalLen,
            //    meta.ml_code_iat, meta.ml_code_len,
            //    meta.ml_result
            //});
            
            //if( meta.ml_result != 0 )
            {
                // send a digest to controller
                digest<digest_t>(1, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 
                                 meta.srcPort, meta.dstPort,
                                 hdr.ipv4.protocol, 
                                 (bit<64>)meta.feature1, hdr.ipv4.totalLen, 
                                 meta.ml_result});
            }
            ipv4_lpm.apply();
        }
    }
}

NvDocaPipeline(
    nv_fixed_parser(),
    main_control()
) main;