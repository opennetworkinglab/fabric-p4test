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

echo 128 > /proc/sys/vm/nr_hugepages
mkdir /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

mkdir /tmp/run
cd /tmp/run
stratum_bf -flagfile=/workdir/stratum.flags > ./stratum_bf.log 2>&1
