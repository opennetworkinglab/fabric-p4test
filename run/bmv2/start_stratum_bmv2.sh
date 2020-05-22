#!/usr/bin/env bash

set -e

/fabric-p4test/run/bmv2/veth_setup.sh

# Clean write-reqs.txt
echo "" > /fabric-p4test/run/bmv2/log/write-reqs.txt

stratum_bmv2 -device_id=1 \
	-chassis_config_file=/fabric-p4test/run/bmv2/chassis_config.txt \
	-forwarding_pipeline_configs_file=/dev/null \
	-persistent_config_dir=/tmp/ \
	-initial_pipeline=/root/dummy.json \
	-cpu_port=255 \
	-external-stratum-urls=0.0.0.0:28000 \
	-local_stratum_url=localhost:28000 \
	-write_req_log_file=/fabric-p4test/run/bmv2/log/p4rt-write-reqs.log \
	-logtostderr=true \
	-bmv2_log_level debug \
	-log_dir=/fabric-p4test/run/bmv2/log &> /fabric-p4test/run/bmv2/log/switch.log
