/*******************************************************************************
 *  INTEL CONFIDENTIAL
 *
 *  Copyright (c) 2021 Intel Corporation
 *  All Rights Reserved.
 *
 *  This software and the related documents are Intel copyrighted materials,
 *  and your use of them is governed by the express license under which they
 *  were provided to you ("License"). Unless the License provides otherwise,
 *  you may not use, modify, copy, publish, distribute, disclose or transmit
 *  this software or the related documents without Intel's prior written
 *  permission.
 *
 *  This software and the related documents are provided as is, with no express
 *  or implied warranties, other than those that are expressly stated in the
 *  License.
 ******************************************************************************/


#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "common/headers.p4"
#include "common/utils.p4"

const int CABLING_CNT = 32;

struct metadata_t {
    bit<32> kaypoh_ptr;
    bit<16> checksum_tcp_tmp;

    tstamp_trunc_t delay_kaypoh;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    // TofinoIngressParser() tofino_parser;
    Checksum() tcp_checksum;

    state start {
        // tofino_parser.apply(pkt, ig_intr_md);
		pkt.extract(ig_intr_md);
		pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);

        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            default : reject;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);

        tcp_checksum.subtract({hdr.tcp.checksum});
        tcp_checksum.subtract({hdr.tcp.window});
        tcp_checksum.subtract({hdr.tcp.seq_no});
        ig_md.checksum_tcp_tmp = tcp_checksum.get();

        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}


// ---------------------------------------------------------------------------
// Ingress
// ---------------------------------------------------------------------------
control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {


    const bit<32> tstamp_diff_table_size = 1 << 10;
    Register<tstamp_trunc_t, bit<32>>(tstamp_diff_table_size, 0) tstamp_diff_table;
    RegisterAction<tstamp_trunc_t, bit<32>, tstamp_trunc_t>(tstamp_diff_table) push_tstamp = {
        void apply(inout tstamp_trunc_t reg_data) {
            reg_data = ig_md.delay_kaypoh;
        }
    };

    DirectRegister<bit<32>>() next_ptr_counter;

    DirectRegisterAction<bit<32>, bit<32>>(next_ptr_counter) get_then_set_ptr = {
        // Retrieve the update pointer then increment the pointer
        void apply(inout bit<32> reg_data, out bit<32> result) {
            result = reg_data;
            reg_data = reg_data + 1;
        }
    };

    action do_direct_cabling(PortId_t port) {
        ig_intr_tm_md.ucast_egress_port = port;
    }

    table direct_cabling {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            do_direct_cabling;
            @defaultonly NoAction;
        }
        const default_action = NoAction();
        size = CABLING_CNT;
    }

    action do_collect_kaypoh() {
        push_tstamp.execute(ig_md.kaypoh_ptr);
    }

    table collect_kaypoh {
        actions = {
            @defaultonly do_collect_kaypoh;
        }
        const default_action = do_collect_kaypoh;
        size = 1;
    }

    action init_kaypoh() {
        hdr.tcp.window = TCP_KAYPOH;
        hdr.tcp.seq_no = (tstamp_trunc_t)ig_intr_md.ingress_mac_tstamp;
    }

    action update_kaypoh() {
        ig_md.delay_kaypoh = (tstamp_trunc_t)ig_intr_md.ingress_mac_tstamp - hdr.tcp.seq_no;  
        ig_md.kaypoh_ptr = get_then_set_ptr.execute();
    }

    table check_kaypoh {
        key = { hdr.tcp.window : exact; }
        actions = {
            @defaultonly init_kaypoh;
            update_kaypoh;
        }
        const default_action = init_kaypoh();
        size = 2;
    }

    apply {
        // normal routing
        direct_cabling.apply();

        // Kaypoh operations
        if (hdr.tcp.isValid()) {
            if (check_kaypoh.apply().hit) {
                collect_kaypoh.apply();
            }
        }
        
    }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    Checksum() tcp_checksum;

    apply {
        if (hdr.tcp.isValid()) {
            hdr.tcp.checksum = tcp_checksum.update({
                hdr.tcp.seq_no,
                hdr.tcp.window,
                ig_md.checksum_tcp_tmp
            });
        }
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser SwitchEgressParser(packet_in        pkt,
    /* User */
    out egress_headers_t          hdr,
    out egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control SwitchEgress(
    /* User */
    inout egress_headers_t                          hdr,
    inout egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

    /*********************  D E P A R S E R  ************************/

control SwitchEgressDeparser(packet_out pkt,
    /* User */
    inout egress_headers_t                       hdr,
    in    egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}

/************ F I N A L   P A C K A G E ******************************/
Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;
