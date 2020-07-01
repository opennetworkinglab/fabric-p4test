bmv2_p4c_out := ${ONOS_ROOT}/pipelines/fabric/impl/src/main/resources/p4c-out
tofino_p4c_out := ${FABRIC_TOFINO}/src/main/resources/p4c-out

define run_tests
$(if $(filter $(DEVICE),tofino),
python -u ptf_runner.py --device $(DEVICE) --port-map $(PORTMAP) \
	--ptf-dir fabric.ptf --cpu-port 320 --device-id 1 \
	--grpc-addr $(GRPCADDR) \
	--p4info $(tofino_p4c_out)/$(1)/tofino/mavericks_sde_9_0_0/p4info.txt \
	--tofino-bin $(tofino_p4c_out)/$(1)/tofino/mavericks_sde_9_0_0/pipe/tofino.bin \
	--tofino-ctx-json $(tofino_p4c_out)/$(1)//tofino/mavericks_sde_9_0_0/pipe/context.json \
	--generate-tv \
	$(2),
python -u ptf_runner.py --device $(DEVICE) --port-map $(PORTMAP) \
	--ptf-dir fabric.ptf --cpu-port 255 --device-id 1 \
	--grpc-addr 127.0.0.1:28000 \
	--p4info $(bmv2_p4c_out)/$(1)/bmv2/default/p4info.txt \
	--bmv2-json $(bmv2_p4c_out)/$(1)/bmv2/default/bmv2.json \
	--generate-tv \
	$(2)
)
endef

.DEFAULT_GOAL := all

_checkenv:
ifndef ONOS_ROOT
	$(error ONOS_ROOT env not defined)
endif
ifndef FABRIC_TOFINO
	$(error FABRIC_TOFINO env not defined)
endif
ifndef DEVICE
	$(eval DEVICE = tofino)
endif
ifndef PORTMAP
	$(eval PORTMAP = port_map.veth.json)
endif
ifndef GRPCADDR
	$(eval GRPCADDR = 127.0.0.1:28000)
endif
include ../../tests/ptf/Makefile.profiles

