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

from ptf.testutils import group
from scapy.contrib.mpls import MPLS

from base_test import autocleanup
from fabric_test import *

vlan_confs = {
    "tagged": [True, True],
    "untagged": [False, False],
    "mixed": [True, False],
}


class FabricBridgingTest(BridgingTest):
    @autocleanup
    def doRunTest(self, tagged1, tagged2, pkt):
        self.runBridgingTest(tagged1, tagged2, pkt)

    def runTest(self):
        print ""
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["tcp", "udp", "icmp"]:
                print "Testing %s packet with VLAN %s.." % (pkt_type, vlan_conf)
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                    pktlen=120)
                self.doRunTest(tagged[0], tagged[1], pkt)


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


class FabricIPv4UnicastTest(IPv4UnicastTest):
    @autocleanup
    def doRunTest(self, pkt, mac_dest, tagged1, tagged2):
        self.runIPv4UnicastTest(
            pkt, mac_dest, prefix_len=24, tagged1=tagged1, tagged2=tagged2)

    def runTest(self):
        print ""
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["tcp", "udp", "icmp"]:
                print "Testing %s packet with VLAN %s..." \
                      % (pkt_type, vlan_conf)
                pkt = getattr(testutils, "simple_%s_packet" % pkt_type)(
                    eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                    ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4,
                    pktlen=MIN_PKT_LEN
                )
                self.doRunTest(pkt, HOST2_MAC, tagged[0], tagged[1])


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
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 300)
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


class FabricIPv4UnicastGroupTestAllPortTcpSport(FabricTest):
    @autocleanup
    def runTest(self):
        # In this test we check that packets are forwarded to all ports when we change
        # one of the 5-tuple header values. In this case tcp-source-port
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(self.port1, SWITCH_MAC, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 300)
        grp_id = 66
        mbrs = {
            2: (self.port2, SWITCH_MAC, HOST2_MAC),
            3: (self.port3, SWITCH_MAC, HOST3_MAC),
        }
        self.add_next_hop_L3_group(300, grp_id, mbrs)
        self.set_egress_vlan_pop(self.port2, vlan_id)
        self.set_egress_vlan_pop(self.port3, vlan_id)
        # tcpsport_toport list is used to learn the tcp_source_port that
        # causes the packet to be forwarded for each port
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


class FabricIPv4UnicastGroupTestAllPortTcpDport(FabricTest):
    @autocleanup
    def runTest(self):
        # In this test we check that packets are forwarded to all ports when we change
        # one of the 5-tuple header values. In this case tcp-dst-port
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(self.port1, SWITCH_MAC, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 300)
        grp_id = 66
        mbrs = {
            2: (self.port2, SWITCH_MAC, HOST2_MAC),
            3: (self.port3, SWITCH_MAC, HOST3_MAC),
        }
        self.add_next_hop_L3_group(300, grp_id, mbrs)
        self.set_egress_vlan_pop(self.port2, vlan_id)
        self.set_egress_vlan_pop(self.port3, vlan_id)
        # tcpdport_toport list is used to learn the tcp_destination_port that
        # causes the packet to be forwarded for each port
        tcpdport_toport = [None, None]
        for i in range(50):
            test_tcp_dport = 1230 + i
            pkt_from1 = testutils.simple_tcp_packet(
                eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=64, tcp_dport=test_tcp_dport)
            exp_pkt_to2 = testutils.simple_tcp_packet(
                eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
                ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63, tcp_dport=test_tcp_dport)
            exp_pkt_to3 = testutils.simple_tcp_packet(
                eth_src=SWITCH_MAC, eth_dst=HOST3_MAC,
                ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63, tcp_dport=test_tcp_dport)
            testutils.send_packet(self, self.port1, str(pkt_from1))
            out_port_indx = testutils.verify_any_packet_any_port(
                self, [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])
            tcpdport_toport[out_port_indx] = test_tcp_dport

        pkt_toport2 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=64, tcp_dport=tcpdport_toport[0])
        pkt_toport3 = testutils.simple_tcp_packet(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=64, tcp_dport=tcpdport_toport[1])
        exp_pkt_to2 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63, tcp_dport=tcpdport_toport[0])
        exp_pkt_to3 = testutils.simple_tcp_packet(
            eth_src=SWITCH_MAC, eth_dst=HOST3_MAC,
            ip_src=HOST1_IPV4, ip_dst=HOST2_IPV4, ip_ttl=63, tcp_dport=tcpdport_toport[1])
        testutils.send_packet(self, self.port1, str(pkt_toport2))
        testutils.send_packet(self, self.port1, str(pkt_toport3))
        # In this assertion we are verifying:
        #  1) all ports of the same group are used almost once
        #  2) consistency of the forwarding decision, i.e. packets with the same 5-tuple
        #     fields are always forwarded out of the same port
        testutils.verify_each_packet_on_each_port(
            self, [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])


class FabricIPv4UnicastGroupTestAllPortIpSrc(FabricTest):
    @autocleanup
    def IPv4UnicastGroupTestAllPortL4SrcIp(self, pkt_type):
        # In this test we check that packets are forwarded to all ports when we change
        # one of the 5-tuple header values and we have an ECMP-like distribution.
        # In this case IP source for tcp and udp packets
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(self.port1, SWITCH_MAC, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 300)
        grp_id = 66
        mbrs = {
            2: (self.port2, SWITCH_MAC, HOST2_MAC),
            3: (self.port3, SWITCH_MAC, HOST3_MAC),
        }
        self.add_next_hop_L3_group(300, grp_id, mbrs)
        self.set_egress_vlan_pop(self.port2, vlan_id)
        self.set_egress_vlan_pop(self.port3, vlan_id)
        # ipsource_toport list is used to learn the ip_src that causes the packet
        # to be forwarded for each port
        ipsource_toport = [None, None]
        for i in range(50):
            test_ipsource = "10.0.1." + str(i)
            pkt_from1 = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                ip_src=test_ipsource, ip_dst=HOST2_IPV4, ip_ttl=64)
            exp_pkt_to2 = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
                ip_src=test_ipsource, ip_dst=HOST2_IPV4, ip_ttl=63)
            exp_pkt_to3 = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=SWITCH_MAC, eth_dst=HOST3_MAC,
                ip_src=test_ipsource, ip_dst=HOST2_IPV4, ip_ttl=63)
            testutils.send_packet(self, self.port1, str(pkt_from1))
            out_port_indx = testutils.verify_any_packet_any_port(
                self, [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])
            ipsource_toport[out_port_indx] = test_ipsource

        pkt_toport2 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=ipsource_toport[0], ip_dst=HOST2_IPV4, ip_ttl=64)
        pkt_toport3 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=ipsource_toport[1], ip_dst=HOST2_IPV4, ip_ttl=64)
        exp_pkt_to2 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
            ip_src=ipsource_toport[0], ip_dst=HOST2_IPV4, ip_ttl=63)
        exp_pkt_to3 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=SWITCH_MAC, eth_dst=HOST3_MAC,
            ip_src=ipsource_toport[1], ip_dst=HOST2_IPV4, ip_ttl=63)
        testutils.send_packet(self, self.port1, str(pkt_toport2))
        testutils.send_packet(self, self.port1, str(pkt_toport3))
        # In this assertion we are verifying:
        #  1) all ports of the same group are used almost once
        #  2) consistency of the forwarding decision, i.e. packets with the same 5-tuple
        #     fields are always forwarded out of the same port
        testutils.verify_each_packet_on_each_port(
            self, [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])

    def runTest(self):
        self.IPv4UnicastGroupTestAllPortL4SrcIp("tcp")
        self.IPv4UnicastGroupTestAllPortL4SrcIp("udp")


class FabricIPv4UnicastGroupTestAllPortIpDst(FabricTest):
    @autocleanup
    def IPv4UnicastGroupTestAllPortL4DstIp(self, pkt_type):
        # In this test we check that packets are forwarded to all ports when we change
        # one of the 5-tuple header values and we have an ECMP-like distribution.
        # In this case IP dest for tcp and udp packets
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(self.port1, SWITCH_MAC, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 300)
        grp_id = 66
        mbrs = {
            2: (self.port2, SWITCH_MAC, HOST2_MAC),
            3: (self.port3, SWITCH_MAC, HOST3_MAC),
        }
        self.add_next_hop_L3_group(300, grp_id, mbrs)
        self.set_egress_vlan_pop(self.port2, vlan_id)
        self.set_egress_vlan_pop(self.port3, vlan_id)
        # ipdst_toport list is used to learn the ip_dst that causes the packet
        # to be forwarded for each port
        ipdst_toport = [None, None]
        for i in range(50):
            test_ipdst = "10.0.2." + str(i)
            pkt_from1 = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
                ip_src=HOST1_IPV4, ip_dst=test_ipdst, ip_ttl=64)
            exp_pkt_to2 = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
                ip_src=HOST1_IPV4, ip_dst=test_ipdst, ip_ttl=63)
            exp_pkt_to3 = getattr(testutils, "simple_%s_packet" % pkt_type)(
                eth_src=SWITCH_MAC, eth_dst=HOST3_MAC,
                ip_src=HOST1_IPV4, ip_dst=test_ipdst, ip_ttl=63)
            testutils.send_packet(self, self.port1, str(pkt_from1))
            out_port_indx = testutils.verify_any_packet_any_port(
                self, [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])
            ipdst_toport[out_port_indx] = test_ipdst

        pkt_toport2 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=ipdst_toport[0], ip_ttl=64)
        pkt_toport3 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=HOST1_MAC, eth_dst=SWITCH_MAC,
            ip_src=HOST1_IPV4, ip_dst=ipdst_toport[1], ip_ttl=64)
        exp_pkt_to2 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=SWITCH_MAC, eth_dst=HOST2_MAC,
            ip_src=HOST1_IPV4, ip_dst=ipdst_toport[0], ip_ttl=63)
        exp_pkt_to3 = getattr(testutils, "simple_%s_packet" % pkt_type)(
            eth_src=SWITCH_MAC, eth_dst=HOST3_MAC,
            ip_src=HOST1_IPV4, ip_dst=ipdst_toport[1], ip_ttl=63)
        testutils.send_packet(self, self.port1, str(pkt_toport2))
        testutils.send_packet(self, self.port1, str(pkt_toport3))
        # In this assertion we are verifying:
        #  1) all ports of the same group are used almost once
        #  2) consistency of the forwarding decision, i.e. packets with the same 5-tuple
        #     fields are always forwarded out of the same port
        testutils.verify_each_packet_on_each_port(
            self, [exp_pkt_to2, exp_pkt_to3], [self.port2, self.port3])

    def runTest(self):
        self.IPv4UnicastGroupTestAllPortL4DstIp("tcp")
        self.IPv4UnicastGroupTestAllPortL4DstIp("udp")


class FabricIPv4MPLSTest(FabricTest):
    @autocleanup
    def runTest(self):
        vlan_id = 10
        self.set_ingress_port_vlan(self.port1, False, 0, vlan_id)
        self.set_forwarding_type(self.port1, SWITCH_MAC, 0x800,
                                 FORWARDING_TYPE_UNICAST_IPV4)
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 400)
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
        self.add_forwarding_routing_v4_entry(HOST2_IPV4, 24, 500)
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


@group("packetio")
class FabricDefaultVlanPacketInTest(FabricTest):
    @autocleanup
    def runTest(self):
        pkt = testutils.simple_eth_packet(pktlen=MIN_PKT_LEN)
        self.add_forwarding_acl_cpu_entry(eth_type=pkt[Ether].type)
        for port in [self.port1, self.port2]:
            testutils.send_packet(self, port, str(pkt))
            self.verify_packet_in(pkt, port)
        testutils.verify_no_other_packets(self)


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


@group("int")
class FabricIntSourceTest(IntTest):
    @autocleanup
    def doRunTest(self, **kwargs):
        self.runIntSourceTest(**kwargs)

    def runTest(self):
        instr_sets = [
            [INT_SWITCH_ID, INT_IG_EG_PORT],
            [INT_SWITCH_ID, INT_IG_EG_PORT, INT_IG_TSTAMP, INT_EG_TSTAMP, INT_QUEUE_OCCUPANCY]
        ]
        print ""
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["udp", "tcp"]:
                for transit in [True, False]:
                    for instructions in instr_sets:
                        print "Testing VLAN=%s, pkt=%s, transit=%s, instructions=%s..." \
                              % (vlan_conf, pkt_type, transit, ",".join([INT_INS_TO_NAME[i] for i in instructions]))
                        pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
                        self.doRunTest(pkt=pkt, instructions=instructions,
                                       with_transit=transit, ignore_csum=True,
                                       tagged1=tagged[0], tagged2=tagged[1])


@group("int")
class FabricIntTransitTest(IntTest):
    @autocleanup
    def doRunTest(self, **kwargs):
        self.runIntTransitTest(**kwargs)

    def runTest(self):
        instr_sets = [
            [INT_SWITCH_ID, INT_IG_EG_PORT],
            [INT_SWITCH_ID, INT_IG_EG_PORT, INT_IG_TSTAMP, INT_EG_TSTAMP, INT_QUEUE_OCCUPANCY]
        ]
        print ""
        for vlan_conf, tagged in vlan_confs.items():
            for pkt_type in ["tcp", "udp"]:
                for prev_hops in [0, 3]:
                    for instructions in instr_sets:
                        print "Testing VLAN=%s, pkt=%s, prev_hops=%s, instructions=%s..." \
                              % (vlan_conf, pkt_type, prev_hops,
                                 ",".join([INT_INS_TO_NAME[i] for i in instructions]))
                        pkt = getattr(testutils, "simple_%s_packet" % pkt_type)()
                        hop_metadata, _ = self.get_int_metadata(
                            instructions, 0xCAFEBABE, 0xDEAD, 0xBEEF)
                        int_pkt = self.get_int_pkt(
                            pkt=pkt, instructions=instructions, max_hop=50,
                            transit_hops=prev_hops, hop_metadata=hop_metadata)
                        self.doRunTest(
                            pkt=int_pkt, tagged1=tagged[0], tagged2=tagged[1],
                            ignore_csum=1)
