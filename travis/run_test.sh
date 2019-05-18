#!/usr/bin/env bash

set -e

TRAVIS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
FP4TEST_DIR=${TRAVIS_DIR}/../
PTF_DIR=${FP4TEST_DIR}/tests/ptf

if [[ -z "${1}" ]]; then
    echo "ERROR: first arg should be either an ONOS branch/commit ID or a directory (starting with /)"
    exit 1
else
    if [[ ${1} == /* ]]; then
        export ONOS_ROOT=${1}
    else
        echo "*** Testing against ONOS commit/branch: ${1}"
        git clone https://github.com/opennetworkinglab/onos /tmp/onos -b ${1}
        export ONOS_ROOT=/tmp/onos
    fi
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

