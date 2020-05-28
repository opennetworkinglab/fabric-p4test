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

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Generate target-tofino.conf
PLATF=${1:-mavericks}

if [ -z "${FABRIC_PROFILE}" ]; then
  echo "FABRIC_PROFILE is not set"
  exit 1
fi
if [ "${FABRIC_PROFILE}" = "all" ]; then
  echo "'all' profile is not supported"
  exit 1
fi

if [ -z "${SDE_VER}" ]; then
  echo "SDE_VER is not set"
  exit 1
fi

if [ -z "${FABRIC_TOFINO}" ]; then
  echo "FABRIC_TOFINO is not set"
  exit 1
fi

BASE_PATH=${FABRIC_TOFINO}/src/main/resources/p4c-out/${FABRIC_PROFILE}/tofino/${PLATF}_sde_${SDE_VER}

# Create P4 Target configuration from template
sed -e "s;%DIR%;${BASE_PATH};g" -e "s;%FABRIC_PROFILE%;${FABRIC_PROFILE};g" "${DIR}"/target_conf_template.conf > /tmp/target-tofino.conf

veth_setup.sh
dma_setup.sh
tofino-model --p4-target-config /tmp/target-tofino.conf &> "${DIR}"/log/tm.log
