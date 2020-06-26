p4c_out := ${ONOS_ROOT}/pipelines/fabric/impl/src/main/resources/p4c-out

define run_tests
	python -u ptf_runner.py --device bmv2 --port-map port_map.veth.json \
		--ptf-dir fabric.ptf --cpu-port 255 --device-id 1 \
		--grpc-addr 127.0.0.1:28000 \
		--p4info $(p4c_out)/$(1)/bmv2/default/p4info.txt \
		--bmv2-json $(p4c_out)/$(1)/bmv2/default/bmv2.json \
		$(2)
endef

.DEFAULT_GOAL := all

_checkenv:
ifndef ONOS_ROOT
	$(error ONOS_ROOT env not defined)
endif

include ../../tests/ptf/Makefile.profiles

