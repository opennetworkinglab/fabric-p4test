#!/bin/bash
# Copyright 2020-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -ex

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"

echo 128 > /proc/sys/vm/nr_hugepages
mkdir /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

# Change workdir to a non-shared volume to improve container disk I/O
# performance, as bf_drivers writes many logs during tests execution.
# Log files will be copied out of this container once stopped (see run.)
mkdir /tmp/workdir
cd /tmp/workdir
stratum_bf \
    -bf_sde_install=/usr \
    -bf_switchd_background=true \
    -bf_switchd_cfg=/usr/share/stratum/tofino_skip_p4_no_bsp.conf \
    -chassis_config_file="${DIR}"/chassis_config.pb.txt \
    -external_stratum_urls=0.0.0.0:28000 \
    -forwarding_pipeline_configs_file=/dev/null \
    -grpc_max_recv_msg_size=256 \
    -log_dir=./ \
    -logtostderr=true \
    -persistent_config_dir=/tmp \
    -write_req_log_file=./p4rt-write-reqs.log \
    > ./stratum_bf.log 2>&1
