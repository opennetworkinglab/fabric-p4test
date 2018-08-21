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
from base_test import autocleanup
from base_test import stringify, ipv4_to_binary
from fabric_test import FabricTest, MIN_PKT_LEN, ETH_TYPE_ARP, FORWARDING_TYPE_UNICAST_IPV4, UDP_GTP_PORT, \
    DEFAULT_MPLS_TTL, ETH_TYPE_IPV4, DEFAULT_PRIORITY, ArpBroadcastTest, IPv4UnicastTest, PacketOutTest, PacketInTest, \
    SpgwMPLSTest, SpgwSimpleTest, make_gtp

INT_META_HDR = xnt.INT_META_HDR
INT_L45_HEAD = xnt.INT_L45_HEAD
INT_L45_TAIL = xnt.INT_L45_TAIL

SWITCH_MAC = "00:00:00:00:aa:01"
HOST1_MAC = "00:00:00:00:00:01"
HOST2_MAC = "00:00:00:00:00:02"
HOST3_MAC = "00:00:00:00:00:03"
HOST1_IPV4 = "10.0.1.1"
HOST2_IPV4 = "10.0.2.1"
HOST3_IPV4 = "10.0.3.1"
HOST4_IPV4 = "10.0.4.1"
S1U_ENB_IPV4 = "119.0.0.10"
S1U_SGW_IPV4 = "140.0.0.2"
UE_IPV4 = "16.255.255.252"


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


class FabricIPv4UnicastTcpTest(IPv4UnicastTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4)
        self.runIPv4UnicastTest(pkt, HOST2_MAC)


class FabricIPv4UnicastUdpTest(IPv4UnicastTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_udp_packet(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4)
        self.runIPv4UnicastTest(pkt, HOST2_MAC)


class FabricIPv4UnicastIcmpTest(IPv4UnicastTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_icmp_packet(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, pktlen=MIN_PKT_LEN)
        self.runIPv4UnicastTest(pkt, HOST2_MAC)


class FabricIPv4UnicastGtpTest(IPv4UnicastTest):
    @autocleanup
    def runTest(self):
        # Assert that GTP packets not meant to be processed by spgw.p4 are
        # forwarded using the outer IP+UDP headers. For spgw.p4 to kick in
        # outer IP dst should be in a subnet defined at compile time (see
        # fabric.p4's parser).
        inner_udp = UDP(sport=5061, dport=5060) / ("\xab" * 128)
        pkt = Ether(src=HOST1_MAC, dst=SWITCH_MAC) / \
              IP(src=HOST3_IPV4, dst=HOST4_IPV4) / \
              UDP(sport=UDP_GTP_PORT, dport=UDP_GTP_PORT) / \
              make_gtp(20 + len(inner_udp), 0xeeffc0f0) / \
              IP(src=HOST1_IPV4, dst=HOST2_IPV4) / \
              inner_udp
        self.runIPv4UnicastTest(pkt, HOST2_MAC)


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


@group("packetio")
class FabricArpPacketOutTest(PacketOutTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_arp_packet(pktlen=MIN_PKT_LEN)
        self.runPacketOutTest(pkt)


@group("packetio")
class FabricShortIpPacketOutTest(PacketOutTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(pktlen=MIN_PKT_LEN)
        self.runPacketOutTest(pkt)


@group("packetio")
class FabricLongIpPacketOutTest(PacketOutTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(pktlen=160)
        self.runPacketOutTest(pkt)


@group("packetio")
class FabricArpPacketInTest(PacketInTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_arp_packet(pktlen=MIN_PKT_LEN)
        self.runPacketInTest(pkt, ETH_TYPE_ARP)


@group("packetio")
class FabricLongIpPacketInTest(PacketInTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(pktlen=160)
        self.runPacketInTest(pkt, ETH_TYPE_IPV4)


@group("packetio")
class FabricShortIpPacketInTest(PacketInTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(pktlen=MIN_PKT_LEN)
        self.runPacketInTest(pkt, ETH_TYPE_IPV4)


@group("packetio")
class FabricTaggedPacketInTest(PacketInTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_ip_packet(dl_vlan_enable=True, vlan_vid=10, pktlen=160)
        self.runPacketInTest(pkt, ETH_TYPE_IPV4, tagged=True, vlan_id=10)


@group("spgw")
class SpgwDownlinkTest(SpgwSimpleTest):
    @autocleanup
    def runTest(self):
        inner_udp = UDP(sport=5061, dport=5060) / ("\xab" * 128)
        pkt = Ether(src=self.DMAC_2, dst=self.SWITCH_MAC_2) / \
              IP(src=S1U_ENB_IPV4, dst=UE_IPV4) / \
              inner_udp
        exp_pkt = Ether(src=self.SWITCH_MAC_1, dst=self.DMAC_1) / \
                  IP(tos=0, id=0x1513, flags=0, frag=0,
                     src=S1U_SGW_IPV4, dst=S1U_ENB_IPV4) / \
                  UDP(sport=UDP_GTP_PORT, dport=UDP_GTP_PORT, chksum=0) / \
                  make_gtp(20 + len(inner_udp), 1) / \
                  IP(src=S1U_ENB_IPV4, dst=UE_IPV4, ttl=63) / \
                  inner_udp
        testutils.send_packet(self, self.port2, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port1)


@group("spgw")
class SpgwUplinkTest(SpgwSimpleTest):
    @autocleanup
    def runTest(self):
        inner_udp = UDP(sport=5060, dport=5061) / ("\xab" * 128)
        pkt = Ether(src=self.DMAC_1, dst=self.SWITCH_MAC_1) / \
              IP(src=S1U_ENB_IPV4, dst=S1U_SGW_IPV4) / \
              UDP(sport=UDP_GTP_PORT, dport=UDP_GTP_PORT) / \
              make_gtp(20 + len(inner_udp), 0xeeffc0f0) / \
              IP(src=UE_IPV4, dst=S1U_ENB_IPV4) / \
              inner_udp
        exp_pkt = Ether(src=self.SWITCH_MAC_2, dst=self.DMAC_2) / \
                  IP(src=UE_IPV4, dst=S1U_ENB_IPV4, ttl=63) / \
                  inner_udp
        testutils.send_packet(self, self.port1, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port2)


@group("spgw")
class SpgwDownlinkMPLSTest(SpgwMPLSTest):
    @autocleanup
    def runTest(self):
        inner_udp = UDP(sport=5061, dport=5060) / ("\xab" * 128)
        pkt = Ether(src=self.DMAC_2, dst=self.SWITCH_MAC_2) / \
              IP(src=S1U_ENB_IPV4, dst=UE_IPV4) / \
              inner_udp
        exp_pkt = Ether(src=self.SWITCH_MAC_1, dst=self.DMAC_1) / \
                  MPLS(label=self.mpls_label, cos=0, s=1, ttl=64) / \
                  IP(tos=0, id=0x1513, flags=0, frag=0,
                     src=S1U_SGW_IPV4, dst=S1U_ENB_IPV4) / \
                  UDP(sport=UDP_GTP_PORT, dport=UDP_GTP_PORT, chksum=0) / \
                  make_gtp(20 + len(inner_udp), 1) / \
                  IP(src=S1U_ENB_IPV4, dst=UE_IPV4, ttl=64) / \
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
              IP(tos=0x04, src=S1U_ENB_IPV4, dst=UE_IPV4) / \
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
                     src=S1U_SGW_IPV4, dst=S1U_ENB_IPV4) / \
                  UDP(sport=UDP_GTP_PORT, dport=UDP_GTP_PORT, chksum=0) / \
                  make_gtp(20 + len(inner_udp) + len(exp_int) + len(payload), 1) / \
                  IP(tos=0x04, src=S1U_ENB_IPV4, dst=UE_IPV4, ttl=64) / \
                  inner_udp / \
                  exp_int / \
                  payload
        # We mask off the timestamps as well as the queue occupancy
        exp_pkt = Mask(exp_pkt)
        offset_metadata = 14 + 4 + 20 + 8 + 8 + 20 + 8 + 4 + 8
        exp_pkt.set_do_not_care((offset_metadata + 9) * 8, 11 * 8)

        testutils.send_packet(self, self.port2, str(pkt))
        testutils.verify_packet(self, exp_pkt, self.port1)
