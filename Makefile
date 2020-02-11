# Copyright 2020-present Open Networking Foundation
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

PROFILES ?= all
TEST ?=
BMV2_LOG_LEVEL ?= debug

COMPOSE_OPTIONS = -f travis/docker-compose.yml

test-bmv2:
	mkdir -p ./travis/log
	BMV2_LOG_LEVEL=${BMV2_LOG_LEVEL} TEST=${TEST} docker-compose ${COMPOSE_OPTIONS} up -d
	BMV2_LOG_LEVEL=${BMV2_LOG_LEVEL} TEST=${TEST} docker-compose ${COMPOSE_OPTIONS} exec tester /fabric-p4test/travis/run_test.sh /onos ${PROFILES}
	BMV2_LOG_LEVEL=${BMV2_LOG_LEVEL} TEST=${TEST} docker-compose ${COMPOSE_OPTIONS} down

cleanup: teardown-tests
	#TODO: add cleanup of logs folder and tests logs pcap etc...
	rm ./travis/log/*
	rm ./tests/ptf/ptf.log
	rm ./tests/ptf/ptf.pcap

teardown-tests:
	docker-compose ${COMPOSE_OPTIONS} down