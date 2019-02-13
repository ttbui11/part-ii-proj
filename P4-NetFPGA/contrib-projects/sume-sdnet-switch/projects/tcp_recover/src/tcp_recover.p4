//
// Copyright (c) 2017 Stephen Ibanez
// All rights reserved.
//
// This software was developed by Stanford University and the University of Cambridge Computer Laboratory 
// under National Science Foundation under Grant No. CNS-0855268,
// the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
// by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"), 
// as part of the DARPA MRC research programme.
//
// @NETFPGA_LICENSE_HEADER_START@
//
// Licensed to NetFPGA C.I.C. (NetFPGA) under one or more contributor
// license agreements.  See the NOTICE file distributed with this work for
// additional information regarding copyright ownership.  NetFPGA licenses this
// file to you under the NetFPGA Hardware-Software License, Version 1.0 (the
// "License"); you may not use this file except in compliance with the
// License.  You may obtain a copy of the License at:
//
//   http://www.netfpga-cic.org
//
// Unless required by applicable law or agreed to in writing, Work distributed
// under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations under the License.
//
// @NETFPGA_LICENSE_HEADER_END@
//


#include <core.p4>
#include <sume_switch.p4>

/*
 * Template P4 project for SimpleSumeSwitch 
 *
 */

typedef bit<48> EthAddr_t; 
typedef bit<32> IPv4Addr_t;

#define IPV4_TYPE 0x0800
#define TCP_TYPE 6

#define FIN_MASK 8w0b0000_0001
#define FIN_POS 0

#define SYN_MASK 8w0b0000_0010
#define SYN_POS 1

#define ACK_MASK 8w0b0001_0000
#define ACK_POS 4

#define REG_READ   8w0
#define REG_WRITE  8w1
#define REG_ADD    8w2

#define HASH_WIDTH 5

#define PKT_SIZE 64

#define nf0 8w0b0000_0001
#define nf1 8w0b0000_0100
#define nf2 8w0b0001_0000
#define nf3 8w0b0100_0000


// hash function
@Xilinx_MaxLatency(1)
@Xilinx_ControlWidth(0)
extern void hash_lrc(in bit<104> in_data, out bit<HASH_WIDTH> result);

// latest_seq_no register (per flow)
@Xilinx_MaxLatency(64)
@Xilinx_ControlWidth(HASH_WIDTH)
extern void seq_no_reg_raw(in bit<HASH_WIDTH> index,
                             in bit<32> newVal,
                             in bit<32> incVal,
                             in bit<8> opCode,
                             out bit<32> result);

// pkt_cached (per flow)
@Xilinx_MaxLatency(64)
@Xilinx_ControlWidth(HASH_WIDTH)
extern void pkt_cached_reg_raw(in bit<HASH_WIDTH> index,
                             in bit<32> newVal,
                             in bit<32> incVal,
                             in bit<8> opCode,
                             out bit<32> result);                         

// latest_ack_no register (to calculate number of pkts need to drop)                    
@Xilinx_MaxLatency(64)
@Xilinx_ControlWidth(HASH_WIDTH)
extern void ack_no_reg_raw(in bit<HASH_WIDTH> index,
                             in bit<32> newVal,
                             in bit<32> incVal,
                             in bit<8> opCode,
                             out bit<32> result);

// ack_cnt register
@Xilinx_MaxLatency(64)
@Xilinx_ControlWidth(HASH_WIDTH)
extern void ack_cnt_reg_raw(in bit<HASH_WIDTH> index,
                         in bit<32> newVal,
                         in bit<32> incVal,
                         in bit<8> opCode,
                         out bit<32> result);

// retransmit_cnt register
@Xilinx_MaxLatency(64)
@Xilinx_ControlWidth(HASH_WIDTH)
extern void retransmit_cnt_reg_raw(in bit<HASH_WIDTH> index,
                         in bit<32> newVal,
                         in bit<32> incVal,
                         in bit<8> opCode,
                         out bit<32> result);                   

// standard Ethernet header
header Ethernet_h { 
    EthAddr_t dstAddr; 
    EthAddr_t srcAddr; 
    bit<16> etherType;
}

// IPv4 header without options
header IPv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> tos; 
    bit<16> totalLen; 
    bit<16> identification; 
    bit<3> flags;
    bit<13> fragOffset; 
    bit<8> ttl;
    bit<8> protocol; 
    bit<16> hdrChecksum; 
    IPv4Addr_t srcAddr; 
    IPv4Addr_t dstAddr;
}

// TCP header without options
header TCP_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

// List of all recognized headers
struct Parsed_packet { 
    Ethernet_h ethernet; 
    IPv4_h ip;
    TCP_h tcp;
}

// user defined metadata: can be used to shared information between
// TopParser, TopPipe, and TopDeparser 
struct user_metadata_t {
    bit<8>  unused;
}

// digest data to be sent to CPU if desired. MUST be 256 bits!
struct digest_data_t {
    bit<72>  unused;
    bit<104> flow_id;
    bit<80> tuser;
}

// Parser Implementation
@Xilinx_MaxPacketRegion(8192)
parser TopParser(packet_in b, 
                 out Parsed_packet p, 
                 out user_metadata_t user_metadata,
                 out digest_data_t digest_data,
                 inout sume_metadata_t sume_metadata) {
    state start {
        b.extract(p.ethernet);
        user_metadata.unused = 0;
        digest_data.unused = 0;
        transition select(p.ethernet.etherType) {
            IPV4_TYPE: parse_ipv4;
            default: reject;
        } 
    }

    state parse_ipv4 {
        b.extract(p.ip);
        transition select(p.ip.protocol) {
            TCP_TYPE: parse_tcp;
            default: reject;
        }
    }

    state parse_tcp {
        b.extract(p.tcp);
        transition accept;
    }
}

// match-action pipeline
control TopPipe(inout Parsed_packet p,
                inout user_metadata_t user_metadata, 
                inout digest_data_t digest_data, 
                inout sume_metadata_t sume_metadata) {

    action set_output_port(port_t port) {
        sume_metadata.dst_port = port;
    }

    action cache_write(port_t port) {
        // digest_data.tuser;
    }

    action cache_read(port_t port) {

    }

    action cache_drop(port_t port, bit<8> drop_count) {

    }

    action nop() {}

    action compute_flow_id(bit<1> i) {
        if (i == 1) { // is an ACK
            digest_data.flow_id = p.ip.dstAddr++p.ip.srcAddr++p.ip.protocol++p.tcp.dstPort++p.tcp.srcPort;
        } else { // 'send' direction
            digest_data.flow_id = p.ip.srcAddr++p.ip.dstAddr++p.ip.protocol++p.tcp.srcPort++p.tcp.dstPort;
        }
    }

    table retransmit {
        key = { digest_data.flow_id: exact; }

        actions = {
            set_output_port;
            nop;
        }
        size = 64;
        default_action = nop;
    }

    apply {
        // if (p.tcp.isValid()) {
        //     // metadata for seq_no index register access
        //     bit<HASH_WIDTH> hash_result;

        //     // check if it's an ACK packet
        //     if ((p.tcp.flags & ACK_MASK) >> ACK_POS == 1) {
        //         // Is an ACK packet
        //         compute_flow_id(1);
                
        //         // compute hash of 5-tuple to obtain index for seq_no register, with src and dst swapped
        //         hash_lrc(digest_data.flow_id, hash_result); 
                
        //         // metadata for register access
        //         bit<32> latestSeqNo;
        //         bit<32> latestAckNo;
        //         bit<32> ackCnt;
        //         bit<32> retransmitCnt;

        //         // if the flow_id is in our match-action table, apply our fast recover, otherwise do nothing
        //         if (retransmit.apply().hit) { 
        //             if (p.tcp.ackNo) {
        //                 // this ACK number is more than latestSeqNo -- update, drop cached pkts and reset counters
        //                 // update

        //                 // calculate number of pkts to drop
        //                 drop_count = (p.tcp.ackNo - latestAckNo)/PKT_SIZE < pktCached ? (p.tcp.ackNo - latestAckNo)/PKT_SIZE : pktCached

        //                 // drop cached pkts
        //                 // cache_drop( ,drop_count);

        //                 // reset counters
        //                 ack_cnt_reg_raw(hash_result, 0, 0, REG_WRITE, ackCnt);
        //                 retransmitCnt(hash_result, 0, 0, REG_WRITE, retransmitCnt);
        //             } else {
        //                 // read ackCnt
        //                 ack_cnt_reg_raw(hash_result, 0, 0, REG_READ, ackCnt);

        //                 if (ackCnt < 3) {
        //                     // if ackCnt < 3, send pkt to src "as-is" & increment ackCnt
        //                     ack_cnt_reg_raw(hash_result, 0, 1, REG_ADD, ackCnt);
        //                 } else {
        //                     // ackCnt >= 3, read retransmitCnt
        //                     retransmit_cnt_reg_raw(hash_result, 0, 0, REG_READ, retransmitCnt);

        //                     if (retransmitCnt == 0) {
        //                         // N = 1 -- haven't retransmitted
        //                         // resend pkt
        //                         cache_read();

        //                         // retransmitCnt++
        //                         retransmit_cnt_reg_raw(hash_result, 0, 1, REG_ADD, retransmitCnt);

        //                         // send this pkt to host with ACK flag = 0
        //                         p.tcp.flags ^= ACK_MASK;
        //                     } else {
        //                         // already retransmitted -- send pkt to src "as-is"
        //                         // reset retransmitCnt
        //                         retransmit_cnt_reg_raw(hash_result, 0, 0, REG_WRITE, retransmitCnt);
        //                     }
        //                 }
        //             }
        //         }
        //     } else { 
        //         // not an ACK packet
        //         compute_flow_id(0);
        //         // compute hash of 5-tuple to obtain index for seq_no register
        //         hash_lrc(digest_data.flow_id, hash_result); 

        //         // metadata for register access
        //         bit<32> latestSeqNo;

        //         // if the flow_id is in our match-action table, apply our fast recover, otherwise do nothing
        //         if (retransmit.apply().hit) {
        //             // read the latest seqNo
        //             seq_no_reg_raw(hash_result, 0, 0, REG_READ, latestSeqNo);

        //             if (p.tcp.seqNo > latestSeqNo) {
        //                 // new package -- add pkt to cache_queue
        //                 cache_write(sume_metadata.dstPort);
        //                 // update latest seqNo
        //                 seq_no_reg_raw(hash_result, p.tcp.seqNo, 0, REG_WRITE, latestSeqNo);
        //             } // else it's an old pkt that we have already cached -- do nothing
        //         } 
        //     }
        // }
    }
}

// Deparser Implementation
@Xilinx_MaxPacketRegion(16384)
control TopDeparser(packet_out b,
                    in Parsed_packet p,
                    in user_metadata_t user_metadata,
                    inout digest_data_t digest_data, 
                    inout sume_metadata_t sume_metadata) { 
    apply {
        b.emit(p.ethernet); 
        b.emit(p.ip);
        b.emit(p.tcp);
    }
}


// Instantiate the switch
SimpleSumeSwitch(TopParser(), TopPipe(), TopDeparser()) main;

