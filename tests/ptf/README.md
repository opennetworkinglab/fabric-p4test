# P4Runtime PTF tests for ONOS fabric.p4

## Dependencies (on the test machine)

- [ptf](https://github.com/p4lang/ptf)
- [scapy with extensions](https://github.com/p4lang/scapy-vxlan)
- [P4Runtime](https://github.com/p4lang/PI#building-p4runtimeproto): the
protobuf / gRPC Python code for P4Runtime must have been generated and installed
in the Python path.
- [BMv2](https://github.com/p4lang/behavioral-model/blob/master/targets/simple_switch_grpc)
- [ONOS](https://github.com/opennetworkinglab/onos): for fabric.p4 code and
pre-compiled artifacts (no need to build ONOS, simply clone the repo)
- Set `ONOS_ROOT` env variable to the location where you cloned the ONOS repo


## Before running the tests

### Fabric profiles

fabric.p4 is available in different profiles. Each profile provides different
forwarding capabilities and is determined by the preprocessor flags used to
compile fabric.p4.

The available profiles are:

| Profile name | p4c preprocessor flags | Description |
| -------------| -----------------------|-------------|
| `fabric` | *None* | Basic fabric profile |
| `fabric-spgw`| `-DWITH_SPGW` | With SPGW user plane functionality |
| `fabric-int`| `-DWITH_INT_SOURCE` `-DWITH_INT_TRANSIT` | With INT (spec v0.5) source and transit functionality  |
| `fabric-spgw-int`| `-DWITH_SPGW` `-DWITH_INT_SOURCE` `-DWITH_INT_TRANSIT` | With both SPGW and INT functionalities |

### Compiling fabric.p4 for BMv2

If running tests on BMv2, you can use the pre-compiled artifacts
(BMv2 JSON and P4Info) distributed with ONOS. These files are located under:

```
$ONOS_ROOT/pipelines/fabric/src/main/resources/p4c-out
```

If you need to make changes to fabric.p4, you can recompile the
P4 program using the following commands:

```
cd $ONOS_ROOT/pipelines/fabric/src/main/resources
make
```

The `make` command will build all profiles. To build only a specific
profile:

```
make <profile-name>
```

### Compile for other targets

Compile fabric.p4 with the desired backend and preprocessor flags. For example,
to compile for Tofino:

```
cd $ONOS_ROOT/pipelines/fabric/src/main/resources/
p4c --target tofino --arch v1model -DWITH_SPGW -o fabric-spgw.out \
    --p4runtime-format text --p4runtime-file fabric-spgw.out/p4info.proto \
    fabric.p4 
```

## Steps to run the tests with BMv2

1. Setup veth interfaces, using the script provided with BMv2. This script
should be executed only once before executing any PTF test, or after a reboot
of the test machine.

    ```
    cd <path to bmv2 repo>/tools
    sudo ./veth_setup.sh
    ```

If using the ONOS-P4 Dev VM, the `veth_setup.sh` script will be located
under `/home/sdn`.

2. Run the PTF tests using a convenient `make` command:

    ```
    cd fabric-p4test/tests/ptf
    make
    ```
    
    The `make` command will execute tests for all fabric profiles. To run tests for
    only a specific profile:

    ```
    make <profile-name>
    ```
    
    Alternatively, you can run the `ptf-runner.py` script with BMv2 arguments.
    For example, to run tests for the `fabric` profile:

    ```
    sudo ./ptf_runner.py --device bmv2 \
        --p4info ${ONOS_ROOT}/pipelines/fabric/src/main/resources/p4c-out/fabric/bmv2/default/p4info.txt \
        --bmv2-json ${ONOS_ROOT}/pipelines/fabric/src/main/resources/p4c-out/fabric/bmv2/default/bmv2.json \
        --ptf-dir fabric.ptf --port-map port_map.veth.json \
        all ^spgw
    ```

## Steps to run the tests with Tofino

1. Start `bf_switchd` (with `--skip-p4`) as you normally do.
   
2. Run `ptf_runner.py` with Tofino arguments and `--skip-test`:

    ```
    sudo ./ptf_runner.py --device tofino \ 
        --p4info p4info.txt \
        --tofino-bin tofino.bin \
        --tofino-ctx-json context.json \
        --ptf-dir fabric.ptf --port-map port_map.veth.json \
        --skip-test
    ```

    This will configure the pipeline on the switch, but will *not* execute the
    tests.

3. Configure switch ports using `bf_switchd` CLI.

4. Execute tests by running `ptf_runner.py` with `--skip-config` (since the
pipeline is already configured):

    ```
    sudo ./ptf_runner.py --device tofino \ 
        --p4info p4info.txt \
        --tofino-bin tofino.bin \
        --tofino-ctx-json context.json \
        --ptf-dir fabric.ptf --port-map port_map.veth.json \
        --skip-config all ^spgw
    ```

## Running the right PTF tests for the right profile

Based on which preprocessor flags you are using to compile fabric.p4 (i.e. which
fabric.p4 profile you are trying to use), some PTF tests will not be
available. For example, you will only be able to run the SPGW tests successfully
if fabric.p4 was compiled with `-DWITH_SPGW`. We have tagged the fabric PTF
tests to enable you to choose which ones to run based on the fabric.p4 profile
you are using. You simply need to provide the appropriate PTF "test specs" at
the end of the `ptf_runner.py` command-line invocation based on your
preprocessor flags as per this table:

| Profile | PTF test specs |
| ------- | -------------- |
| `fabric` | `all ^spgw ^int` |
| `fabric-spgw` | `all ^int` |
| `fabric-int` | `all ^spgw` |
| `fabric-spgw-int` | `all` |

For an example of how PTF test specs are used, you can refer to [this
Makefile](./Makefile) used for BMv2 tests.

## Port map JSON file

This file is required to let PTF know which test interface corresponds to which
P4 dataplane port number. Consider the following test topology:

```
             ASIC under test
******************************************
148          149          134          135
 |            |            |            |
 |            |            |            |
 |            |            |            |
ens2f0       ens2f1       ens2f2       ens2f3
******************************************
              PTF test server
```

For this topology one may use the following port map JSON file:
```
[
    {
        "ptf_port": 0,
        "p4_port": 148,
        "iface_name": "ens2f0"
    },
    {
        "ptf_port": 1,
        "p4_port": 149,
        "iface_name": "ens2f1"
    },
    {
        "ptf_port": 2,
        "p4_port": 134,
        "iface_name": "ens2f2"
    },
    {
        "ptf_port": 3,
        "p4_port": 135,
        "iface_name": "ens2f3"
    }
]
```

The `"ptf_port"` is the id used to reference the port in the Python PTF
tests. As of now, `"ptf_port"` must be equal to the index of the entry in the
port map JSON array of interfaces. Port numbers must never be used directly when
calling PTF Python functions (e.g. `send_packet`); instead, when writing your
own tests, call the `swports` method which will map the `"ptf_port"` to the
`"p4_port"` based on the provided port map JSON file.
