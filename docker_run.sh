#!/usr/bin/env bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if [[ -z "${ONOS_ROOT}" ]]; then
    echo "ERROR: ONOS_ROOT env not defined"
    exit 1
fi

# Stratum BMv2
stratumImageName=opennetworking/mn-stratum:latest
stratumRunName=stratum-bmv2-${RANDOM}

# PTF Tester
testerImageName=${PTFTEST_IMAGE:-onosproject/fabric-p4test:latest}
testerRunName=fabric-p4test-${RANDOM}

function stop() {
        echo " Stopping ${testerRunName}..."
        docker stop -t0 ${testerRunName}
        echo " Stopping ${stratumRunName}..."
        docker stop -t0 ${stratumRunName}
}
trap stop INT

# Run stratum-bmv2
docker run --name ${stratumRunName} -d --privileged --rm \
    -p 28000:28000 \
    --entrypoint "/fabric-p4test/travis/run_stratum_bmv2.sh" \
    -v ${DIR}:/fabric-p4test \
    ${stratumImageName}
sleep 2

# Run and show log (also stored in run.log)
docker run --name ${testerRunName} -d --privileged --rm \
    --network "container:${stratumRunName}" \
    -v ${DIR}:/fabric-p4test \
    -v ${ONOS_ROOT}:/onos \
    ${testerImageName} \
    bash /fabric-p4test/travis/run_test.sh /onos ${@}
docker logs -f ${testerRunName} | tee ${DIR}/run.log

stop