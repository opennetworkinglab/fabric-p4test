BASE_CMD = ./ptf_runner.py --port-map port_map.veth.json --ptf-dir fabric.ptf --cpu-port 255 --device-id 1
BASE_P4C_OUT_PATH = ${ONOS_ROOT}/pipelines/fabric/src/main/resources/p4c-out
FABRIC_OUT = ${BASE_P4C_OUT_PATH}/fabric/bmv2/default
FABRIC_SPGW_OUT = ${BASE_P4C_OUT_PATH}/fabric-spgw/bmv2/default
FABRIC_INT_OUT = ${BASE_P4C_OUT_PATH}/fabric-int/bmv2/default
FABRIC_SPGW_INT_OUT = ${BASE_P4C_OUT_PATH}/fabric-spgw-int/bmv2/default

all: fabric fabric-spgw fabric-int fabric-spgw-int

fabric: set-cmd
ifndef TEST
	$(eval TEST = all ^spgw ^int)
endif
	${PTF_BMV2_CMD} \
		--p4info ${FABRIC_OUT}/p4info.txt \
		--bmv2-json ${FABRIC_OUT}/bmv2.json \
		${TEST}

fabric-spgw: set-cmd
ifndef TEST
	$(eval TEST = all ^int)
endif
	${PTF_BMV2_CMD} \
		--p4info ${FABRIC_SPGW_OUT}/p4info.txt \
		--bmv2-json ${FABRIC_SPGW_OUT}/bmv2.json \
		${TEST}

fabric-spgw-int: set-cmd
ifndef TEST
	$(eval TEST = all ^int-full)
endif
	${PTF_BMV2_CMD} \
		--p4info ${FABRIC_SPGW_INT_OUT}/p4info.txt \
		--bmv2-json ${FABRIC_SPGW_INT_OUT}/bmv2.json \
		${TEST}

fabric-int: set-cmd
ifndef TEST
	$(eval TEST = all ^spgw ^int-full)
endif
	${PTF_BMV2_CMD} \
		--p4info ${FABRIC_INT_OUT}/p4info.txt \
		--bmv2-json ${FABRIC_INT_OUT}/bmv2.json \
		${TEST}

set-cmd: set-device check-onos-root
ifndef DOCKER_RUN
	$(eval PTF_BMV2_CMD = sudo -E ${BASE_CMD})
else
	$(eval PTF_BMV2_CMD = ${BASE_CMD})
endif
	$(eval PTF_BMV2_CMD = ${PTF_BMV2_CMD} --device ${DEVICE_TYPE})

set-device:
ifndef STRATUM_ROOT
	$(eval DEVICE_TYPE = bmv2)
else
	$(warning STRATUM_ROOT env is set, using stratum_bmv2...)
	$(eval DEVICE_TYPE = stratum-bmv2)
endif

check-onos-root:
ifndef ONOS_ROOT
	$(error ONOS_ROOT env not defined)
endif