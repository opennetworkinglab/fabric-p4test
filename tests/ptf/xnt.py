# Copyright 2013-present Barefoot Networks, Inc.
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

# eXtensible Network Telemetry

from scapy.packet import *
from scapy.fields import *

class INT_META_HDR(Packet):
    name = "INT_metadata_header"
    fields_desc = [ BitField("ver", 0, 2), BitField("rep", 0, 2),
                    BitField("c", 0, 1), BitField("e", 0, 1),
                    BitField("rsvd1", 0, 5), BitField("ins_cnt", 1, 5),
                    BitField("max_hop_cnt", 32, 8),
                    BitField("total_hop_cnt", 0, 8),
                    ShortField("inst_mask", 0x8000),
                    ShortField("rsvd2", 0x0000)]

class INT_L45_HEAD(Packet):
    name = "INT_L45_HEAD"
    fields_desc = [ XByteField("int_type", 0x01),
                   XByteField("rsvd0", 0x00),
                   XByteField("length", 0x00),
                   XByteField("rsvd1", 0x00) ]

class INT_L45_TAIL(Packet):
    name = "INT_L45_TAIL"
    fields_desc = [ XByteField("next_proto", 0x01),
                   XShortField("proto_param", 0x0000),
                   XByteField("rsvd", 0x00) ]
