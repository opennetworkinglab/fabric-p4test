# P4Runtime PTF tests for fabric

## Dependencies (on the test machine)

- [ptf](https://github.com/p4lang/ptf)
- [scapy with extensions](https://github.com/p4lang/scapy-vxlan)
- [P4Runtime](https://github.com/p4lang/PI#building-p4runtimeproto): the
protobuf / gRPC Python code for P4Runtime must have been generated and installed
in the Python path.

## Steps to run the tests

1. Compile fabric.p4 with desired preprocessor flags. All the compiler outputs
(p4info, binary config and context JSON) must be placed in the same output
directory. For example:

```
p4c --target tofino-v1model fabric.p4 -DWITH_INT_TRANSIT -o fabric-DWITH_INT_TRANSIT.out \
    --p4runtime-format text --p4runtime-file fabric-DWITH_INT_TRANSIT.out/p4info.proto
```

2. Start switchd (with `--skip-p4`) as you normally do. Also start the software
model (`tofino-model`) if that's what you are using to run the tests.

3. Run the PTF tests:

```
sudo ./ptf_runner.py --p4c-out fabric-DWITH_INT_TRANSIT.out/ \
    --ptf-dir fabric.ptf/ --port-map <path to port map JSON> all ^spgw
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

| Preprocessor flags passed to p4c | PTF test specs |
| -------------------------------- | -------------- |
| None | all ^spgw ^int_transit |
| -DWITH_SPGW | all ^int_transit |
| -DWITH_INT_TRANSIT | all ^spgw |
| -DWITH_SPGW -DWITH_INT_TRANSIT | all |

## Port map JSON file

This file is required to let PTF know which test interface corresponds to which
P4 dataplane port number. Consider the follwing test topology:

```
              BF Tofino ASIC
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
