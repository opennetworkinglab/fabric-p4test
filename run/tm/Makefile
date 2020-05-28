p4c_out := ${FABRIC_TOFINO}/src/main/resources/p4c-out
platf := mavericks

define run_tests
	python -u ptf_runner.py --device tofino --port-map port_map.veth.json \
		--ptf-dir fabric.ptf --cpu-port 320 --device-id 1 \
		--grpc-addr "127.0.0.1:28000" \
		--p4info ${p4c_out}/${1}/tofino/$(platf)_sde_${SDE_VER}/p4info.txt \
		--tofino-bin ${p4c_out}/${1}/tofino/$(platf)_sde_${SDE_VER}/pipe/tofino.bin \
		--tofino-ctx-json ${p4c_out}/${1}/tofino/$(platf)_sde_${SDE_VER}/pipe/context.json \
		$(2)
endef

_checkenv:
ifndef FABRIC_TOFINO
	$(error FABRIC_TOFINO env not defined)
endif

include ../../tests/ptf/Makefile.profiles
