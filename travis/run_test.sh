#!/usr/bin/env bash

set -e

TRAVIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
FP4TEST_DIR=${TRAVIS_DIR}/../
PTF_DIR=${FP4TEST_DIR}/tests/ptf

# First argument is the location of the onos source tree
ONOS_ROOT=${1}
# Pass all other arguments to make
TEST_CASE=${@:2}

err_report() {
    echo
    echo "************************************************"
    echo "BMV2 LOG"
    echo "************************************************"
    cat ${FP4TEST_DIR}/travis/log/switch.log
    echo
    echo "************************************************"
    echo "PTF LOG"
    echo "************************************************"
    cat ${PTF_DIR}/ptf.log

    echo "************************************************"
    echo "SOME PTF TESTS FAILED :("
    echo "************************************************"
    exit 1
}

trap 'err_report' ERR
cd ${PTF_DIR}

echo "************************************************"
echo "STARTING PTF TESTS..."
echo "************************************************"
sleep 2
ONOS_ROOT=${ONOS_ROOT} make -f Makefile ${TEST_CASE} 2>&1

echo "************************************************"
echo "ALL PTF TESTS PASSED :)"
echo "************************************************"

