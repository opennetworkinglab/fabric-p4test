#!/usr/bin/env bash
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

veth_setup.sh
dma_setup.sh

# Copy files outside of shared volume to improve container disk I/O performance
cp -r /p4c-out /tmp
ls /tmp

mkdir /tmp/run

# Change workdir to a non-shared volume to improve container disk I/O
# performance, as tofino-model performs a lot of log writes for each packet
cd /tmp/run && tofino-model --p4-target-config "${DIR}"/tm_conf.json
