PTF_BMV2_CMD = sudo -E ./ptf_runner.py --port-map port_map.veth.json --ptf-dir fabric.ptf --cpu-port 255 --device-id 1 --device
BASE_P4C_OUT_PATH = ${ONOS_ROOT}/pipelines/fabric/src/main/resources/p4c-out
FABRIC_OUT = ${BASE_P4C_OUT_PATH}/fabric/bmv2/default
FABRIC_SPGW_OUT = ${BASE_P4C_OUT_PATH}/fabric-spgw/bmv2/default
FABRIC_INT_OUT = ${BASE_P4C_OUT_PATH}/fabric-int/bmv2/default
FABRIC_SPGW_INT_OUT = ${BASE_P4C_OUT_PATH}/fabric-spgw-int/bmv2/default

all: fabric fabric-spgw fabric-int fabric-spgw-int

fabric: set-device
ifndef TEST
	$(eval TEST = all ^spgw ^int)
endif
	${PTF_BMV2_CMD} ${DEVICE_TYPE} \
		--p4info ${FABRIC_OUT}/p4info.txt \
		--bmv2-json ${FABRIC_OUT}/bmv2.json \
		${TEST}

fabric-spgw: set-device
ifndef TEST
	$(eval TEST = all ^int)
endif
	${PTF_BMV2_CMD} ${DEVICE_TYPE} \
		--p4info ${FABRIC_SPGW_OUT}/p4info.txt \
		--bmv2-json ${FABRIC_SPGW_OUT}/bmv2.json \
		${TEST}

fabric-spgw-int: set-device
ifndef TEST
	$(eval TEST = all ^int-full)
endif
	${PTF_BMV2_CMD} ${DEVICE_TYPE} \
		--p4info ${FABRIC_SPGW_INT_OUT}/p4info.txt \
		--bmv2-json ${FABRIC_SPGW_INT_OUT}/bmv2.json \
		${TEST}

fabric-int: set-device
ifndef TEST
	$(eval TEST = all ^spgw ^int-full)
endif
	${PTF_BMV2_CMD} ${DEVICE_TYPE} \
		--p4info ${FABRIC_INT_OUT}/p4info.txt \
		--bmv2-json ${FABRIC_INT_OUT}/bmv2.json \
		${TEST}

set-device:
ifndef STRATUM_ROOT
	$(eval DEVICE_TYPE = bmv2)
else
	$(warning STRATUM_ROOT env is set, using stratum_bmv2...)
	$(eval DEVICE_TYPE = stratum-bmv2)
endif
