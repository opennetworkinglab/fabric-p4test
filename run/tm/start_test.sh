#!/usr/bin/env bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
FP4TEST_DIR=${DIR}/../../
PTF_DIR=${FP4TEST_DIR}/tests/ptf

err_report() {
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

make -f "${DIR}"/Makefile ${@} 2>&1

echo "************************************************"
echo "ALL PTF TESTS PASSED :)"
echo "************************************************"

