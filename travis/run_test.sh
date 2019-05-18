#!/usr/bin/env bash

set -e

TRAVIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
FP4TEST_DIR=${TRAVIS_DIR}/../
PTF_DIR=${FP4TEST_DIR}/tests/ptf

if [[ -z "${1}" ]]; then
    echo "ERROR: first argument should be the location of ONOS root directory"
    exit 1
else
    export ONOS_ROOT=${1}
fi

# Pass all other arguments to make
TEST_CASE=${@:2}

bash ${TRAVIS_DIR}/veth_setup.sh > /dev/null

err_report() {
    echo
    echo "************************************************"
    echo "BMV2 LOG"
    echo "************************************************"
    cat /tmp/bmv2-ptf.log
    echo
    echo "************************************************"
    echo "PTF LOG"
    echo "************************************************"
    cat ${PTF_DIR}/ptf.log

    echo "************************************************"
    echo "SOME TESTS FAILED :("
    echo "************************************************"
    exit 1
}

trap 'err_report' ERR
cd ${PTF_DIR}

echo "************************************************"
echo "STARTING TESTS..."
echo "************************************************"

make ${TEST_CASE} 2>&1

echo "************************************************"
echo "ALL TESTS PASSED :)"
echo "************************************************"

