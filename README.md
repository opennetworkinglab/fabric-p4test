# PTF tests for ONOS fabric.p4

This project contains PTF-based tests for `fabric.p4`, a P4 program used by ONOS
to provide connectivity in a leaf-spine fabric topology of P4Runtime-enabled
switches:

<https://wiki.onosproject.org/x/wgBkAQ>

PTF is a framework for data plane testing:

<https://github.com/p4lang/PTF>

## Run tests using BMv2 and Docker

We provide a Docker image with everything needed to run the PTF tests using the
BMv2 `simple_switch_grpc` target.

[![](https://images.microbadger.com/badges/image/onosproject/fabric-p4test.svg)](https://microbadger.com/images/onosproject/fabric-p4test)

Test cases are defined inside the directory `tests/ptf/fabric.ptf`. To run the
tests use the following steps.

### Steps

1. Install Docker on your machine.

2. Obtain the `fabric.p4` pre-compiled artifacts for BMv2 (`bmv2.json` and
   `p4info.txt`). These files are distributed with ONOS:

    ```
    git clone https://github.com/opennetworkinglab/onos
    ```

3. Set the `ONOS_ROOT` environment variable to the location where you just cloned the ONOS source:

    ```
    export ONOS_ROOT=<path-to-onos>
    ```

4. Run PTF tests:

    ```
    ./docker_run.sh <profile-or-test-case>
    ```

    `profile` is the `fabric.p4` profile to test. To learn more about
    "profiles" check the instructions available inside the `tests/ptf`
    directory.
    
    For example, to run all test cases for all profiles:

    ```
    ./docker_run.sh all
    ```

    To run all test cases for the `fabric-spgw` profile:

    ```
    ./docker_run.sh fabric-spgw
    ```

    To run a specific test case against a specific fabric profile (or `all`),
    for example `test.FabricBridgingTest` for the basic `fabric` profile:

    ```
    ./docker_run.sh fabric TEST=test.FabricBridgingTest
    ```

## Run tests on other targets

To run tests on targets other than BMv2 (e.g. Tofino), check the instructions
available inside the `tests/ptf` directory.

## Status

All test cases are executed daily on different ONOS branches using Travis CI.
The current status is:

[![Build Status](https://travis-ci.org/opennetworkinglab/fabric-p4test.svg?branch=master)](https://travis-ci.org/opennetworkinglab/fabric-p4test)

## Support

For help running the tests please write to the P4 Brigade
mailing list:

<https://groups.google.com/a/onosproject.org/forum/#!forum/brigade-p4>
