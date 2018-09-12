PTF_BMV2_CMD = sudo ./ptf_runner.py --device bmv2 --port-map port_map.veth.json --ptf-dir fabric.ptf --cpu-port 255
BASE_P4C_OUT_PATH = ${ONOS_ROOT}/pipelines/fabric/src/main/resources/p4c-out
FABRIC_OUT = ${BASE_P4C_OUT_PATH}/fabric/bmv2/default
FABRIC_SPGW_OUT = ${BASE_P4C_OUT_PATH}/fabric-spgw/bmv2/default
FABRIC_INT_OUT = ${BASE_P4C_OUT_PATH}/fabric-int/bmv2/default

all: fabric fabric-spgw fabric-int

fabric:
ifndef TEST
	$(eval TEST = all ^spgw ^int)
endif
	${PTF_BMV2_CMD} \
		--p4info ${FABRIC_OUT}/p4info.txt \
		--bmv2-json ${FABRIC_OUT}/bmv2.json \
		${TEST}

fabric-spgw:
ifndef TEST
	$(eval TEST = all ^int)
endif
	${PTF_BMV2_CMD} \
		--p4info ${FABRIC_SPGW_OUT}/p4info.txt \
		--bmv2-json ${FABRIC_SPGW_OUT}/bmv2.json \
		${TEST}

fabric-int:
ifndef TEST
	$(eval TEST = all ^spgw ^int-full)
endif
	${PTF_BMV2_CMD} \
		--p4info ${FABRIC_INT_OUT}/p4info.txt \
		--bmv2-json ${FABRIC_INT_OUT}/bmv2.json \
		${TEST}
