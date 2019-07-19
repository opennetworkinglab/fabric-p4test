base_cmd := ./ptf_runner.py --port-map port_map.veth.json --ptf-dir fabric.ptf --cpu-port 255 --device-id 1
p4c_out := ${ONOS_ROOT}/pipelines/fabric/src/main/resources/p4c-out
bmv2_out := bmv2/default

define run_tests
	$(ptf_bmv2_cmd) \
		--p4info $(p4c_out)/$(1)/$(bmv2_out)/p4info.txt \
		--bmv2-json $(p4c_out)/$(1)/$(bmv2_out)/bmv2.json \
		$(2)
endef

all: fabric fabric-bng fabric-spgw fabric-int fabric-spgw-int

fabric: set-cmd
ifndef TEST
	$(eval TEST = all ^spgw ^int ^bng ^dth)
endif
	$(call run_tests,fabric,$(TEST))

fabric-bng: set-cmd
ifndef TEST
	$(eval TEST = all ^spgw ^int ^xconnect)
endif
	$(call run_tests,fabric-bng,$(TEST))

fabric-spgw: set-cmd
ifndef TEST
	$(eval TEST = all ^int ^bng ^dth)
endif
	$(call run_tests,fabric-spgw,$(TEST))

fabric-spgw-int: set-cmd
ifndef TEST
	$(eval TEST = all ^int-full ^bng ^dth)
endif
	$(call run_tests,fabric-spgw-int,$(TEST))

fabric-int: set-cmd
ifndef TEST
	$(eval TEST = all ^spgw ^int-full ^bng ^dth)
endif
	$(call run_tests,fabric-int,$(TEST))

set-cmd: set-device check-onos-root
ifndef DOCKER_RUN
	$(eval ptf_bmv2_cmd = sudo -E ${base_cmd})
else
	$(eval ptf_bmv2_cmd = ${base_cmd})
endif
	$(eval ptf_bmv2_cmd = $(ptf_bmv2_cmd) --device ${device_type})

set-device:
ifndef STRATUM_ROOT
	$(eval device_type = bmv2)
else
	$(warning STRATUM_ROOT env is set, using stratum_bmv2...)
	$(eval device_type = stratum-bmv2)
endif

check-onos-root:
ifndef ONOS_ROOT
	$(error ONOS_ROOT env not defined)
endif