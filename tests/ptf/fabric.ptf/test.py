# Copyright 2013-present Barefoot Networks, Inc.
# Copyright 2018-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import struct
import unittest

import ptf.testutils as testutils
from p4.v1 import p4runtime_pb2
from ptf.mask import Mask
from ptf.testutils import group
from scapy.contrib.mpls import MPLS
from scapy.layers.inet import IP, UDP, Ether

# In case the "correct" version of scapy (from p4lang) is not installed, we
# provide the INT header formats in xnt.py
# import scapy.main
# scapy.main.load_contrib("xnt")
# INT_META_HDR = scapy.contrib.xnt.INT_META_HDR
# INT_L45_HEAD = scapy.contrib.xnt.INT_L45_HEAD
# INT_L45_TAIL = scapy.contrib.xnt.INT_L45_TAIL
import xnt
from base_test import P4RuntimeTest, autocleanup
from base_test import stringify, ipv4_to_binary, mac_to_binary

INT_META_HDR = xnt.INT_META_HDR
INT_L45_HEAD = xnt.INT_L45_HEAD
INT_L45_TAIL = xnt.INT_L45_TAIL

# constants from fabric.p4
DEFAULT_PRIORITY = 10
FORWARDING_TYPE_BRIDGING = 0
FORWARDING_TYPE_UNICAST_IPV4 = 2
DEFAULT_MPLS_TTL = 64

SWITCH_MAC = "00:00:00:00:aa:01"
HOST1_MAC = "00:00:00:00:00:01"
HOST2_MAC = "00:00:00:00:00:02"
HOST3_MAC = "00:00:00:00:00:03"
HOST1_IPV4 = "10.0.1.1"
HOST2_IPV4 = "10.0.2.1"


def make_gtp(msg_len, teid, flags=0x30, msg_type=0xff):
    """Convenience function since GTP header has no scapy support"""
    return struct.pack(">BBHL", flags, msg_type, msg_len, teid)


class FabricTest(P4RuntimeTest):
    def setUp(self):
        super(FabricTest, self).setUp()
        self.port1 = self.swports(1)
        self.port2 = self.swports(2)
        self.port3 = self.swports(3)

    def setup_int(self):
        self.send_request_add_entry_to_action(
            "int_egress.int_prep", None, "int_egress.int_transit",
            [("switch_id", stringify(1, 4))])

        req = p4runtime_pb2.WriteRequest()
        for i in xrange(16):
            base = "int_set_header_0003_i"
            mf = self.Exact("hdr.int_header.instruction_mask_0003",
                            stringify(i, 1))
            action = "int_metadata_insert." + base + str(i)
            self.push_update_add_entry_to_action(
                req,
                "int_metadata_insert.int_inst_0003", [mf],
                action, [])
        self.write_request(req)

        req = p4runtime_pb2.WriteRequest()
        for i in xrange(16):
            base = "int_set_header_0407_i"
            mf = self.Exact("hdr.int_header.instruction_mask_0407",
                            stringify(i, 1))
            action = "int_metadata_insert." + base + str(i)
            self.push_update_add_entry_to_action(
                req,
                "int_metadata_insert.int_inst_0407", [mf],
                action, [])
        self.write_request(req)

    def set_ingress_port_vlan(self, ingress_port, vlan_valid=False,
                              vlan_id=0,
                              new_vlan_id=0):
        ingress_port_ = stringify(ingress_port, 2)
        vlan_valid_ = '\x01' if vlan_valid else '\x00'
        vlan_id_ = stringify(vlan_id, 2)
        vlan_id_mask_ = stringify(4095 if vlan_valid else 0, 2)
        new_vlan_id_ = stringify(new_vlan_id, 2)
        action_name = "set_vlan" if vlan_valid else "push_internal_vlan"
        self.send_request_add_entry_to_action(
            "filtering.ingress_port_vlan",
            [self.Exact("standard_metadata.ingress_port", ingress_port_),
             self.Exact("hdr.vlan_tag.is_valid", vlan_valid_),
             self.Ternary("hdr.vlan_tag.vlan_id", vlan_id_, vlan_id_mask_)],
            "filtering." + action_name, [("new_vlan_id", new_vlan_id_)],
            DEFAULT_PRIORITY)

    def set_egress_vlan_pop(self, egress_port, vlan_id):
        egress_port = stringify(egress_port, 2)
        vlan_id = stringify(vlan_id, 2)
        self.send_request_add_entry_to_action(
            "egress_next.egress_vlan",
            [self.Exact("hdr.vlan_tag.vlan_id", vlan_id),
             self.Exact("standard_metadata.egress_port", egress_port)],
            "egress_next.pop_vlan", [])

    def set_forwarding_type(self, ingress_port, eth_dstAddr, ethertype=0x800,
                            fwd_type=FORWARDING_TYPE_UNICAST_IPV4):
        ingress_port_ = stringify(ingress_port, 2)
        eth_dstAddr_ = mac_to_binary(eth_dstAddr)
        ethertype_ = stringify(ethertype, 2)
        fwd_type_ = stringify(fwd_type, 1)
        self.send_request_add_entry_to_action(
            "filtering.fwd_classifier",
            [self.Exact("standard_metadata.ingress_port", ingress_port_),
             self.Exact("hdr.ethernet.dst_addr", eth_dstAddr_),
             self.Exact("fabric_metadata.original_ether_type", ethertype_)],
            "filtering.set_forwarding_type", [("fwd_type", fwd_type_)])

    def add_bridging_entry(self, vlan_id, eth_dstAddr, eth_dstAddr_mask,
                           next_id):
        vlan_id_ = stringify(vlan_id, 2)
        eth_dstAddr_ = mac_to_binary(eth_dstAddr)
        eth_dstAddr_mask_ = mac_to_binary(eth_dstAddr_mask)
        next_id_ = stringify(next_id, 4)
        self.send_request_add_entry_to_action(
            "forwarding.bridging",
            [self.Exact("hdr.vlan_tag.vlan_id", vlan_id_),
             self.Ternary("hdr.ethernet.dst_addr",
                          eth_dstAddr_, eth_dstAddr_mask_)],
            "forwarding.set_next_id_bridging", [("next_id", next_id_)],
            DEFAULT_PRIORITY)

    def add_forwarding_unicast_v4_entry(self, ipv4_dstAddr, ipv4_pLen,
                                        next_id):
        ipv4_dstAddr_ = ipv4_to_binary(ipv4_dstAddr)
        next_id_ = stringify(next_id, 4)
        self.send_request_add_entry_to_action(
            "forwarding.unicast_v4",
            [self.Lpm("hdr.ipv4.dst_addr", ipv4_dstAddr_, ipv4_pLen)],
            "forwarding.set_next_id_unicast_v4", [("next_id", next_id_)])

    def add_forwarding_acl_cpu_entry(self, eth_type=None):
        eth_type_ = stringify(eth_type, 2)
        eth_type_mask = stringify(0xFFFF, 2)
        self.send_request_add_entry_to_action(
            "forwarding.acl",
            [self.Ternary("fabric_metadata.original_ether_type", eth_type_, eth_type_mask)],
            "forwarding.send_to_controller", [],
            DEFAULT_PRIORITY)

    def add_next_hop(self, next_id, egress_port):
        next_id_ = stringify(next_id, 4)
        egress_port_ = stringify(egress_port, 2)
        self.send_request_add_entry_to_action(
            "next.simple",
            [self.Exact("fabric_metadata.next_id", next_id_)],
            "next.output_simple", [("port_num", egress_port_)])

    def add_next_multicast(self, next_id, mcast_group_id):
        next_id_ = stringify(next_id, 4)
        mcast_group_id_ = stringify(mcast_group_id, 2)
        self.send_request_add_entry_to_action(
            "next.multicast",
            [self.Exact("fabric_metadata.next_id", next_id_)],
            "next.set_mcast_group", [("gid", mcast_group_id_)])

    def add_next_hop_L3(self, next_id, egress_port, smac, dmac):
        next_id_ = stringify(next_id, 4)
        egress_port_ = stringify(egress_port, 2)
        smac_ = mac_to_binary(smac)
        dmac_ = mac_to_binary(dmac)
        self.send_request_add_entry_to_action(
            "next.simple",
            [self.Exact("fabric_metadata.next_id", next_id_)],
            "next.l3_routing_simple",
            [("port_num", egress_port_), ("smac", smac_), ("dmac", dmac_)])

    # next_hops is a dictionary mapping mbr_id to (egress_port, smac, dmac)
    # we can break this method into several ones (group creation, etc.) if there
    # is a need when adding new tests in the future
    def add_next_hop_L3_group(self, next_id, grp_id, next_hops=None):
        next_id_ = stringify(next_id, 4)
        if next_hops is not None:
            for mbr_id, params in next_hops.items():
                egress_port, smac, dmac = params
                egress_port_ = stringify(egress_port, 2)
                smac_ = mac_to_binary(smac)
                dmac_ = mac_to_binary(dmac)
                self.send_request_add_member(
                    "next.ecmp_selector", mbr_id, "next.l3_routing_hashed",
                    [("port_num", egress_port_), ("smac", smac_), ("dmac", dmac_)])
        self.send_request_add_group("next.ecmp_selector", grp_id,
                                    grp_size=32, mbr_ids=next_hops.keys())
        self.send_request_add_entry_to_group(
            "next.hashed",
            [self.Exact("fabric_metadata.next_id", next_id_)],
            grp_id)

    def add_next_hop_mpls_v4(self, next_id, egress_port, smac, dmac, label):
        next_id_ = stringify(next_id, 4)
        egress_port_ = stringify(egress_port, 2)
        smac_ = mac_to_binary(smac)
        dmac_ = mac_to_binary(dmac)
        label_ = stringify(label, 3)
        self.send_request_add_entry_to_action(
            "next.simple",
            [self.Exact("fabric_metadata.next_id", next_id_)],
            "next.mpls_routing_v4_simple",
            [("port_num", egress_port_), ("smac", smac_), ("dmac", dmac_),
             ("label", label_)])

    # next_hops is a dictionary mapping mbr_id to (egress_port, smac, dmac,
    # label)
    def add_next_hop_mpls_v4_group(self, next_id, grp_id, next_hops=None):
        next_id_ = stringify(next_id, 4)
        if next_hops is not None:
            for mbr_id, params in next_hops.items():
                egress_port, smac, dmac, label = params
                egress_port_ = stringify(egress_port, 2)
                smac_ = mac_to_binary(smac)
                dmac_ = mac_to_binary(dmac)
                label_ = stringify(label, 3)
                self.send_request_add_member(
                    "next.ecmp_selector", mbr_id, "next.mpls_routing_v4_hashed",
                    [("port_num", egress_port_), ("smac", smac_), ("dmac", dmac_),
                     ("label", label_)])
        self.send_request_add_group("next.ecmp_selector", grp_id,
                                    grp_size=32, mbr_ids=next_hops.keys())
        self.send_request_add_entry_to_group(
            "next.hashed",
            [self.Exact("fabric_metadata.next_id", next_id_)],
            grp_id)

    def add_mcast_group(self, group_id, ports):
        req = p4runtime_pb2.WriteRequest()
        req.device_id = self.device_id
        update = req.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        pre_entry = update.entity.packet_replication_engine_entry
        mg_entry = pre_entry.multicast_group_entry
        mg_entry.multicast_group_id = group_id
        for port in ports:
            replica = mg_entry.replicas.add()
            replica.egress_port = port
            replica.instance = 0
        return req, self.write_request(req)


class FabricL2UnicastTest(FabricTest):
    @autocleanup
    def runTest(self):
        mac_addr_mask = ":".join(["ff"] * 6)
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_ingress_port_vlan(self.port2, False, 0, vlan_id)
        # miss on filtering.fwd_classifier => bridging
        self.add_bridging_entry(vlan_id, HOST1_MAC, mac_addr_mask, 10)
        self.add_bridging_entry(vlan_id, HOST2_MAC, mac_addr_mask, 20)
        self.add_next_hop(10, self.port1)
        self.add_next_hop(20, self.port2)
        self.set_egress_vlan_pop(self.port1, vlan_id)
        self.set_egress_vlan_pop(self.port2, vlan_id)

        pkt_1to2 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=HOST2_MAC, ip_ttl=64)
        exp_pkt_1to2 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=HOST2_MAC, ip_ttl=63)

        testutils.send_packet(self, self.port1, str(pkt_1to2))
        testutils.verify_packets(self, exp_pkt_1to2, [self.port2])

        pkt_2to1 = testutils.simple_tcp_packet(
            eth_src=HOST2_MAC, eth_dst=HOST1_MAC, ip_ttl=64)
        exp_pkt_2to1 = testutils.simple_tcp_packet(
            eth_src=HOST2_MAC, eth_dst=HOST1_MAC, ip_ttl=63)

        testutils.send_packet(self, self.port2, str(pkt_2to1))
        testutils.verify_packets(self, exp_pkt_2to1, [self.port1])


class FabricL2UnicastVlanTest(FabricTest):
    @autocleanup
    def runTest(self):
        mac_addr_mask = ":".join(["ff"] * 6)
        vlan_id = 10
        # set internal VLAN for port 2 only since packet from port 1 is tagged
        self.set_ingress_port_vlan(self.port2, False, 0, vlan_id)
        # miss on filtering.fwd_classifier => bridging
        self.add_bridging_entry(vlan_id, HOST1_MAC, mac_addr_mask, 10)
        self.add_bridging_entry(vlan_id, HOST2_MAC, mac_addr_mask, 20)
        self.add_next_hop(10, self.port1)
        self.add_next_hop(20, self.port2)
        # pops VLAN on port 2 since port 2 is an untagged port
        self.set_egress_vlan_pop(self.port2, vlan_id)

        pkt_1to2 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=HOST2_MAC, dl_vlan_enable=True,
            vlan_vid=vlan_id, ip_ttl=64)
        exp_pkt_1to2 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=HOST2_MAC,
            ip_ttl=63, pktlen=96)  # packet length will decrease

        testutils.send_packet(self, self.port1, str(pkt_1to2))
        testutils.verify_packets(self, exp_pkt_1to2, [self.port2])

        pkt_2to1 = testutils.simple_tcp_packet(
            eth_src=HOST2_MAC, eth_dst=HOST1_MAC, ip_ttl=64)
        exp_pkt_2to1 = testutils.simple_tcp_packet(
            eth_src=HOST2_MAC, eth_dst=HOST1_MAC, dl_vlan_enable=True,
            vlan_vid=vlan_id, ip_ttl=63, pktlen=104)  # packet length will increase

        testutils.send_packet(self, self.port2, str(pkt_2to1))
        testutils.verify_packets(self, exp_pkt_2to1, [self.port1])


class ArpBroadcastTest(FabricTest):
    def runArpBroadcastTest(self, tagged_ports, untagged_ports):
        zero_mac_addr = ":".join(["00"] * 6)
        vlan_id = 10
        next_id = vlan_id
        mcast_group_id = vlan_id
        all_ports = set(tagged_ports + untagged_ports)
        arp_pkt = testutils.simple_arp_packet(pktlen=76)
        # Account for VLAN header size in total pktlen
        vlan_arp_pkt = testutils.simple_arp_packet(vlan_vid=vlan_id, pktlen=80)

        for port in tagged_ports:
            self.set_ingress_port_vlan(port, True, vlan_id, vlan_id)
        for port in untagged_ports:
            self.set_ingress_port_vlan(port, False, 0, vlan_id)
        self.add_bridging_entry(vlan_id, zero_mac_addr, zero_mac_addr, next_id)
        self.add_next_multicast(next_id, mcast_group_id)
        self.add_mcast_group(mcast_group_id, all_ports)
        for port in untagged_ports:
            self.set_egress_vlan_pop(port, vlan_id)

        for inport in all_ports:
            pkt_to_send = vlan_arp_pkt if inport in tagged_ports else arp_pkt
            testutils.send_packet(self, inport, str(pkt_to_send))
            # Packet should be received on all ports expect the ingress one.
            verify_tagged_ports = set(tagged_ports)
            verify_tagged_ports.discard(inport)
            for tport in verify_tagged_ports:
                testutils.verify_packet(self, vlan_arp_pkt, tport)
            verify_untagged_ports = set(untagged_ports)
            verify_untagged_ports.discard(inport)
            for uport in verify_untagged_ports:
                testutils.verify_packet(self, arp_pkt, uport)
        testutils.verify_no_other_packets(self)


@group("multicast")
class FabricArpBroadcastUntaggedTest(ArpBroadcastTest):
    @autocleanup
    def runTest(self):
        self.runArpBroadcastTest(
            tagged_ports=[],
            untagged_ports=[self.port1, self.port2, self.port3])


@group("multicast")
class FabricArpBroadcastTaggedTest(ArpBroadcastTest):
    @autocleanup
    def runTest(self):
        self.runArpBroadcastTest(
            tagged_ports=[self.port1, self.port2, self.port3],
            untagged_ports=[])


@group("multicast")
class FabricArpBroadcastMixedTest(ArpBroadcastTest):
    @autocleanup
    def runTest(self):
        self.runArpBroadcastTest(
            tagged_ports=[self.port2, self.port3],
            untagged_ports=[self.port1])


class FabricIPv4UnicastTest(FabricTest):
    @autocleanup
    def runTest(self):
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_ingress_port_vlan(self.port2, False, 0, vlan_id)
        self.set_forwarding_type(self.port1, SWITCH_MAC, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.set_forwarding_type(self.port2, SWITCH_MAC, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.add_forwarding_unicast_v4_entry(HOST1_IPV4, 24, 100)
        self.add_forwarding_unicast_v4_entry(HOST2_IPV4, 24, 200)
        self.add_next_hop_L3(100, self.port1, SWITCH_MAC, HOST1_MAC)
        self.add_next_hop_L3(200, self.port2, SWITCH_MAC, HOST2_MAC)
        self.set_egress_vlan_pop(self.port1, vlan_id)
        self.set_egress_vlan_pop(self.port2, vlan_id)

        pkt_1to2 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=64)
        exp_pkt_1to2 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63)

        testutils.send_packet(self, self.port1, str(pkt_1to2))
        testutils.verify_packets(self, exp_pkt_1to2, [self.port2])

        pkt_2to1 = testutils.simple_tcp_packet(
            eth_src=HOST2_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST2_IPV4, ip_dst=HOST1_IPV4, ip_ttl=64)
        exp_pkt_2to1 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC, eth_dst=HOST1_MAC,
            ip_src=HOST2_IPV4, ip_dst=HOST1_IPV4, ip_ttl=63)

        testutils.send_packet(self, self.port2, str(pkt_2to1))
        testutils.verify_packets(self, exp_pkt_2to1, [self.port1])


class FabricIPv4UnicastGroupTest(FabricTest):
    @autocleanup
    def runTest(self):
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(self.port1, SWITCH_MAC, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.add_forwarding_unicast_v4_entry(HOST2_IPV4, 24, 300)
        grp_id = 66
        mbrs = {
            2: (self.port2, SWITCH_MAC, HOST2_MAC),
            3: (self.port3, SWITCH_MAC, HOST3_MAC),
        }
        self.add_next_hop_L3_group(300, grp_id, mbrs)
        self.set_egress_vlan_pop(self.port2, vlan_id)
        self.set_egress_vlan_pop(self.port3, vlan_id)

        pkt_from1 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=64)
        exp_pkt_to2 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63)
        exp_pkt_to3 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC, eth_dst=HOST3_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63)

        testutils.send_packet(self, self.port1, str(pkt_from1))
        testutils.verify_any_packet_any_port(
            self, [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])


class FabricIPv4UnicastGroupTestAllPort(FabricTest):
    @autocleanup
    def runTest(self):
        vlan_id = 10
        out_port = ["port2", "port3", "port4"]
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(self.port1, SWITCH_MAC, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.add_forwarding_unicast_v4_entry(HOST2_IPV4, 24, 300)
        grp_id = 66
        mbrs = {
            2: (self.port2, SWITCH_MAC, HOST2_MAC),
            3: (self.port3, SWITCH_MAC, HOST3_MAC),
        }
        self.add_next_hop_L3_group(300, grp_id, mbrs)
        self.set_egress_vlan_pop(self.port2, vlan_id)
        self.set_egress_vlan_pop(self.port3, vlan_id)
        # tcpsport_toport list is used to learn the tcp_source_port that causes the packet 
        # to be forwarded for each port
        tcpsport_toport = [None, None]
        for i in range(50):
            test_tcp_sport = 1230 + i
            pkt_from1 = testutils.simple_tcp_packet(
                eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=64, tcp_sport=test_tcp_sport)
            exp_pkt_to2 = testutils.simple_tcp_packet(
                eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
                ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63, tcp_sport=test_tcp_sport)
            exp_pkt_to3 = testutils.simple_tcp_packet(
                eth_src=SWITCH_MAC, eth_dst=HOST3_MAC,
                ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63, tcp_sport=test_tcp_sport)
            testutils.send_packet(self, self.port1, str(pkt_from1))
            out_port_indx = testutils.verify_any_packet_any_port(
                self, [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])
            tcpsport_toport[out_port_indx] = test_tcp_sport

        pkt_toport2 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=64, tcp_sport=tcpsport_toport[0])
        pkt_toport3 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=64, tcp_sport=tcpsport_toport[1])
        exp_pkt_to2 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63, tcp_sport=tcpsport_toport[0])
        exp_pkt_to3 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC, eth_dst=HOST3_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63, tcp_sport=tcpsport_toport[1])
        testutils.send_packet(self, self.port1, str(pkt_toport2))
        testutils.send_packet(self, self.port1, str(pkt_toport3))
        # In this assertion we are verifying:
        #  1) all ports of the same group are used almost once
        #  2) consistency of the forwarding decision, i.e. packets with the same 5-tuple
        #     fields are always forwarded out of the same port
        testutils.verify_each_packet_on_each_port(
            self, [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])


class FabricIPv4MPLSTest(FabricTest):
    @autocleanup
    def runTest(self):
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(self.port1, SWITCH_MAC, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.add_forwarding_unicast_v4_entry(HOST2_IPV4, 24, 400)
        mpls_label = 0xaba
        self.add_next_hop_mpls_v4(
            400, self.port2, SWITCH_MAC, HOST2_MAC, mpls_label)
        self.set_egress_vlan_pop(self.port2, vlan_id)

        pkt_1to2 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=64)
        exp_pkt_1to2 = testutils.simple_mpls_packet(
            eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
            mpls_tags=[{
                "label": mpls_label,
                "tc": 0,
                "s": 1,
                "ttl": DEFAULT_MPLS_TTL}],
            inner_frame=pkt_1to2[IP:])

        testutils.send_packet(self, self.port1, str(pkt_1to2))
        testutils.verify_packets(self, exp_pkt_1to2, [self.port2])


class FabricIPv4MPLSGroupTest(FabricTest):
    @autocleanup
    def runTest(self):
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(self.port1, SWITCH_MAC, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.add_forwarding_unicast_v4_entry(HOST2_IPV4, 24, 500)
        grp_id = 77
        mpls_label = 0xaba
        mbrs = {2: (self.port2, SWITCH_MAC, HOST2_MAC, mpls_label)}
        self.add_next_hop_mpls_v4_group(500, grp_id, mbrs)
        self.set_egress_vlan_pop(self.port2, vlan_id)

        pkt_1to2 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=64)
        exp_pkt_1to2 = testutils.simple_mpls_packet(
            eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
            mpls_tags=[{
                "label": mpls_label,
                "tc": 0,
                "s": 1,
                "ttl": DEFAULT_MPLS_TTL}],
            inner_frame=pkt_1to2[IP:])

        testutils.send_packet(self, self.port1, str(pkt_1to2))
        testutils.verify_packets(self, exp_pkt_1to2, [self.port2])


class PacketOutTest(FabricTest):
    def runPacketOutTest(self, pkt):
        for port in [self.port1, self.port2]:
            port_hex = stringify(port, 2)
            packet_out = p4runtime_pb2.PacketOut()
            packet_out.payload = str(pkt)
            egress_physical_port = packet_out.metadata.add()
            egress_physical_port.metadata_id = 1
            egress_physical_port.value = port_hex

            self.send_packet_out(packet_out)
            testutils.verify_packet(self, pkt, port)
        testutils.verify_no_other_packets(self)


@group("packetio")
class FabricArpPacketOutTest(PacketOutTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_arp_packet(pktlen=80)
        self.runPacketOutTest(pkt)


@group("packetio")
class FabricShortIpPacketOutTest(PacketOutTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(pktlen=80)
        self.runPacketOutTest(pkt)


@group("packetio")
class FabricLongIpPacketOutTest(PacketOutTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(pktlen=160)
        self.runPacketOutTest(pkt)


class PacketInTest(FabricTest):
    def runPacketInTest(self, pkt):
        vlan_id = 10
        self.add_forwarding_acl_cpu_entry(eth_type=pkt.type)
        for port in [self.port1, self.port2]:
            self.set_ingress_port_vlan(port, False, 0, vlan_id)
            testutils.send_packet(self, port, str(pkt))
            self.verify_packet_in(pkt, port)
            testutils.verify_no_other_packets(self)


@group("packetio")
class FabricArpPacketInTest(PacketInTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_arp_packet(pktlen=80)
        self.runPacketInTest(pkt)


@group("packetio")
class FabricLongIpPacketInTest(PacketInTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(pktlen=160)
        self.runPacketInTest(pkt)


@group("packetio")
class FabricShortIpPacketInTest(PacketInTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(pktlen=80)
        self.runPacketInTest(pkt)


class SpgwTest(FabricTest):
    def setUp(self):
        super(SpgwTest, self).setUp()
        self.S1U_ENB_IPV4 = "192.168.102.11"
        self.S1U_SGW_IPV4 = "192.168.102.13"
        self.END_POINT_IPV4 = "16.255.255.252"
        self.SWITCH_MAC_1 = "c2:42:59:2d:3a:84"
        self.SWITCH_MAC_2 = "3a:c1:e2:53:e1:50"
        self.DMAC_1 = "52:54:00:05:7b:59"
        self.DMAC_2 = "52:54:00:29:c9:b7"

        self.set_forwarding_type(self.port1, self.SWITCH_MAC_1, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.set_forwarding_type(self.port2, self.SWITCH_MAC_2, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)


class SpgwSimpleTest(SpgwTest):
    def setUp(self):
        super(SpgwSimpleTest, self).setUp()

        self.add_forwarding_unicast_v4_entry(self.S1U_ENB_IPV4, 32, 1)
        self.add_forwarding_unicast_v4_entry(self.END_POINT_IPV4, 32, 2)
        self.add_next_hop_L3(1, self.port2, self.SWITCH_MAC_2, self.DMAC_2)
        self.add_next_hop_L3(2, self.port1, self.SWITCH_MAC_1, self.DMAC_1)

        req = p4runtime_pb2.WriteRequest()
        req.device_id = self.device_id
        s1u_enb_ipv4_ = ipv4_to_binary(self.S1U_ENB_IPV4)
        s1u_sgw_ipv4_ = ipv4_to_binary(self.S1U_SGW_IPV4)
        end_point_ipv4_ = ipv4_to_binary(self.END_POINT_IPV4)
        self.push_update_add_entry_to_action(
            req,
            "spgw_ingress.ue_filter_table",
            [self.Lpm("ipv4.dst_addr", end_point_ipv4_, 32)],
            "NoAction", [])
        self.push_update_add_entry_to_action(
            req,
            "spgw_ingress.s1u_filter_table",
            [self.Exact("spgw_meta.s1u_sgw_addr", s1u_sgw_ipv4_)],
            "NoAction", [])
        self.push_update_add_entry_to_action(
            req,
            "spgw_ingress.dl_sess_lookup",
            [self.Exact("ipv4.dst_addr", end_point_ipv4_)],
            "spgw_ingress.set_dl_sess_info",
            [("teid", stringify(1, 4)), ("s1u_enb_addr", s1u_enb_ipv4_),
             ("s1u_sgw_addr", s1u_sgw_ipv4_)])
        self.write_request(req)


@group("spgw")
class SpgwDownlinkTest(SpgwSimpleTest):
    @autocleanup
    def runTest(self):
        inner_udp = UDP(sport=5061, dport=5060) / ("\xab" * 128)
        pkt = Ether(src=self.DMAC_2, dst=self.SWITCH_MAC_2) / \
              IP(src=self.S1U_ENB_IPV4, dst=self.END_POINT_IPV4) / \
              inner_udp
        exp_pkt = Ether(src=self.SWITCH_MAC_1, dst=self.DMAC_1) / \
                  IP(tos=0, id=0x1513, flags=0, frag=0,
                     src=self.S1U_SGW_IPV4, dst=self.S1U_ENB_IPV4) / \
                  UDP(sport=2152, dport=2152, chksum=0) / \
                  make_gtp(20 + len(inner_udp), 1) / \
                  IP(src=self.S1U_ENB_IPV4, dst=self.END_POINT_IPV4, ttl=63) / \
                  inner_udp
        testutils.send_packet(self, self.port2, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port1)


@group("spgw")
class SpgwUplinkTest(SpgwSimpleTest):
    @autocleanup
    def runTest(self):
        inner_udp = UDP(sport=5060, dport=5061) / ("\xab" * 128)
        pkt = Ether(src=self.DMAC_1, dst=self.SWITCH_MAC_1) / \
              IP(src=self.S1U_ENB_IPV4, dst=self.S1U_SGW_IPV4) / \
              UDP(sport=2152, dport=2152) / \
              make_gtp(20 + len(inner_udp), 0xeeffc0f0) / \
              IP(src=self.END_POINT_IPV4, dst=self.S1U_ENB_IPV4) / \
              inner_udp
        exp_pkt = Ether(src=self.SWITCH_MAC_2, dst=self.DMAC_2) / \
                  IP(src=self.END_POINT_IPV4, dst=self.S1U_ENB_IPV4, ttl=63) / \
                  inner_udp
        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port2)


class SpgwMPLSTest(SpgwTest):
    def setUp(self):
        super(SpgwMPLSTest, self).setUp()

        self.mpls_label = 204

        # internal vlan required for MPLS
        self.set_ingress_port_vlan(self.port1, vlan_valid=False,
                                   vlan_id=0, new_vlan_id=4094)
        self.set_ingress_port_vlan(self.port2, vlan_valid=False,
                                   vlan_id=0, new_vlan_id=20)
        self.add_forwarding_unicast_v4_entry(self.S1U_ENB_IPV4, 32, 1)
        self.add_forwarding_unicast_v4_entry(self.END_POINT_IPV4, 32, 2)
        self.add_next_hop_L3(1, self.port2, self.SWITCH_MAC_2, self.DMAC_2)
        self.add_next_hop_mpls_v4(2, self.port1, self.SWITCH_MAC_1, self.DMAC_1,
                                  self.mpls_label)

        req = p4runtime_pb2.WriteRequest()
        req.device_id = self.device_id
        s1u_enb_ipv4_ = ipv4_to_binary(self.S1U_ENB_IPV4)
        s1u_sgw_ipv4_ = ipv4_to_binary(self.S1U_SGW_IPV4)
        end_point_ipv4_ = ipv4_to_binary(self.END_POINT_IPV4)
        self.push_update_add_entry_to_action(
            req,
            "spgw_ingress.ue_filter_table",
            [self.Lpm("ipv4.dst_addr", end_point_ipv4_, 32)],
            "NoAction", [])
        self.push_update_add_entry_to_action(
            req,
            "spgw_ingress.s1u_filter_table",
            [self.Exact("spgw_meta.s1u_sgw_addr", s1u_sgw_ipv4_)],
            "NoAction", [])
        self.push_update_add_entry_to_action(
            req,
            "spgw_ingress.dl_sess_lookup",
            [self.Exact("ipv4.dst_addr", end_point_ipv4_)],
            "spgw_ingress.set_dl_sess_info",
            [("teid", stringify(1, 4)), ("s1u_enb_addr", s1u_enb_ipv4_),
             ("s1u_sgw_addr", s1u_sgw_ipv4_)])
        self.write_request(req)


@group("spgw")
class SpgwDownlinkMPLSTest(SpgwMPLSTest):
    @autocleanup
    def runTest(self):
        inner_udp = UDP(sport=5061, dport=5060) / ("\xab" * 128)
        pkt = Ether(src=self.DMAC_2, dst=self.SWITCH_MAC_2) / \
              IP(src=self.S1U_ENB_IPV4, dst=self.END_POINT_IPV4) / \
              inner_udp
        exp_pkt = Ether(src=self.SWITCH_MAC_1, dst=self.DMAC_1) / \
                  MPLS(label=self.mpls_label, cos=0, s=1, ttl=64) / \
                  IP(tos=0, id=0x1513, flags=0, frag=0,
                     src=self.S1U_SGW_IPV4, dst=self.S1U_ENB_IPV4) / \
                  UDP(sport=2152, dport=2152, chksum=0) / \
                  make_gtp(20 + len(inner_udp), 1) / \
                  IP(src=self.S1U_ENB_IPV4, dst=self.END_POINT_IPV4, ttl=64) / \
                  inner_udp
        testutils.send_packet(self, self.port2, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port1)


@group("spgw")
@unittest.skip("INT transit capability not yet supported")
class SpgwDownlinkMPLS_INT_Test(SpgwMPLSTest):
    @autocleanup
    def runTest(self):
        self.setup_int()

        dport = 5060

        # int_type=hop-by-hop
        int_shim = INT_L45_HEAD(int_type=1, length=4)
        # ins_cnt: 5 = switch id + ports + q occupancy + ig port + eg port)
        # max_hop_count: 3
        # total_hop_count: 0
        # instruction_mask_0003: 0xd = switch id (0), ports (1), q occupancy (3)
        # instruction_mask_0407: 0xc = ig timestamp (4), eg timestamp (5)
        int_header = "\x00\x05\x03\x00\xdc\x00\x00\x00"
        # IP proto (UDP), UDP dport (4096)
        int_tail = INT_L45_TAIL(next_proto=17, proto_param=dport)

        payload = "\xab" * 128
        inner_udp = UDP(sport=5061, dport=dport, chksum=0)
        # IP tos is 0x04 to enable INT
        pkt = Ether(src=self.DMAC_2, dst=self.SWITCH_MAC_2) / \
              IP(tos=0x04, src=self.S1U_ENB_IPV4, dst=self.END_POINT_IPV4) / \
              inner_udp / \
              int_shim / int_header / int_tail / \
              payload

        exp_int_shim = INT_L45_HEAD(int_type=1, length=9)
        # total_hop_count: 1
        exp_int_header = "\x00\x05\x03\x01\xdc\x00\x00\x00"
        # switch id: 1
        exp_int_metadata = "\x00\x00\x00\x01"
        # ig port: port2, eg port: port2
        exp_int_metadata += stringify(self.port2, 2) + stringify(self.port1, 2)
        # q id: 0, q occupancy: ?
        exp_int_metadata += "\x00\x00\x00\x00"
        # ig timestamp: ?
        # eg timestamp: ?
        exp_int_metadata += "\x00\x00\x00\x00" * 2

        exp_int = exp_int_shim / exp_int_header / exp_int_metadata / int_tail

        exp_pkt = Ether(src=self.SWITCH_MAC_1, dst=self.DMAC_1) / \
                  MPLS(label=self.mpls_label, cos=0, s=1, ttl=64) / \
                  IP(tos=0, id=0x1513, flags=0, frag=0,
                     src=self.S1U_SGW_IPV4, dst=self.S1U_ENB_IPV4) / \
                  UDP(sport=2152, dport=2152, chksum=0) / \
                  make_gtp(20 + len(inner_udp) + len(exp_int) + len(payload), 1) / \
                  IP(tos=0x04, src=self.S1U_ENB_IPV4, dst=self.END_POINT_IPV4, ttl=64) / \
                  inner_udp / \
                  exp_int / \
                  payload
        # We mask off the timestamps as well as the queue occupancy
        exp_pkt = Mask(exp_pkt)
        offset_metadata = 14 + 4 + 20 + 8 + 8 + 20 + 8 + 4 + 8
        exp_pkt.set_do_not_care((offset_metadata + 9) * 8, 11 * 8)

        testutils.send_packet(self, self.port2, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port1)
