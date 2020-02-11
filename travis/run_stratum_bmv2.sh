#!/usr/bin/env bash
/travis/veth_setup.sh;

stratum_bmv2 -device_id=1 \
	-chassis_config_file=/travis/chassis_config.txt \
	-forwarding_pipeline_configs_file=/dev/null \
	-persistent_config_dir=/tmp/ \
	-initial_pipeline=/root/dummy.json \
	-cpu_port=255 \
	-external-stratum-urls=0.0.0.0:28000 \
	-local_stratum_url=localhost:28000 \
	-write_req_log_file=/travis/log/write-reqs.txt \
	-logtosyslog=false \
	-logtostderr=true \
	-bmv2_log_level ${BMV2_LOG_LEVEL} \
	-log_dir=/travis/log &> /travis/log/switch.log