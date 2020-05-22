#!/usr/bin/env bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
FP4TEST_DIR=${DIR}/../../
PTF_DIR=${FP4TEST_DIR}/tests/ptf

# First argument is the location of the onos source tree
ONOS_ROOT=${1}
# Pass all other arguments to make
TEST_CASE=${@:2}


err_report() {
    echo
    echo "************************************************"
    echo "STRATUM-BMV2 LOG"
    echo "************************************************"
    cat "${DIR}"/log/stratum_bmv2.log
    echo
    echo "************************************************"
    echo "PTF LOG"
    echo "************************************************"
    cat "${PTF_DIR}"/ptf.log

    echo "************************************************"
    echo "SOME PTF TESTS FAILED :("
    echo "************************************************"
    exit 1
}

trap 'err_report' ERR
cd "${PTF_DIR}"

echo "************************************************"
echo "STARTING PTF TESTS..."
echo "************************************************"

ONOS_ROOT=${ONOS_ROOT} make ${TEST_CASE} 2>&1

echo "************************************************"
echo "ALL PTF TESTS PASSED :)"
echo "************************************************"

