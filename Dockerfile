# Copyright 2019-present Open Networking Foundation
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

# Docker image to run PTF-based data plane tests for ONOS fabric.p4

FROM bitnami/minideb:stretch as builder

ENV BUILD_DEPS \
    python-pip \
    python-setuptools \
    git
RUN install_packages $BUILD_DEPS

RUN mkdir -p /ouput

ENV PIP_DEPS \
    git+https://github.com/p4lang/scapy-vxlan \
    git+https://github.com/p4lang/ptf.git
RUN pip install --no-cache-dir --root /output $PIP_DEPS

FROM opennetworking/p4mn:stable as runtime

LABEL maintainer="onos-dev@onosproject.org"
LABEL description="Docker image to run PTF-based data plane tests for ONOS fabric.p4"
LABEL url="https://github.com/opennetworkinglab/fabric-p4test"

ENV RUNTIME_DEPS \
    make \
    python-setuptools
RUN install_packages $RUNTIME_DEPS

COPY --from=builder /output /

ENV DOCKER_RUN true

ENTRYPOINT []