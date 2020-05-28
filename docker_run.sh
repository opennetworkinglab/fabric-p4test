#!/usr/bin/env bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if [[ -z "${ONOS_ROOT}" ]]; then
    echo "ERROR: ONOS_ROOT env not defined"
    exit 1
fi

radomNumber=${RANDOM}

# Stratum BMv2
# Use image sha to pin a specific stratum_bmv2 build and have reproducible runs.
# TODO: instrument CI to test on both a stable version and the latest one
stratumImageName=opennetworking/mn-stratum:latest@sha256:1bba2e2c06460c73b0133ae22829937786217e5f20f8f80fcc3063dcf6707ebe
stratumRunName=stratum-bmv2-${radomNumber}

# PTF Tester
testerImageName=${FP4TEST_DOCKER_IMG:-onosproject/fabric-p4test:latest}
testerRunName=fabric-p4test-${radomNumber}

function ctrl_c() {
        echo " Stopping ${testerRunName}..."
        docker stop -t0 ${testerRunName}
        docker rm ${testerRunName}
        echo " Stopping ${stratumRunName}..."
        docker stop -t0 ${stratumRunName}
}
trap ctrl_c INT

# Run stratum-bmv2
echo " Starting ${stratumRunName}..."
docker run --name ${stratumRunName} -d --privileged --rm \
    --entrypoint "/fabric-p4test/travis/run_stratum_bmv2.sh" \
    -v ${DIR}:/fabric-p4test \
    ${stratumImageName}
sleep 2

# Run and show log (also stored in run.log)
echo " Starting ${testerRunName}..."
docker run --name ${testerRunName} -d --privileged \
    --network "container:${stratumRunName}" \
    -v ${DIR}:/fabric-p4test \
    -v ${ONOS_ROOT}:/onos \
    ${testerImageName} \
    bash /fabric-p4test/travis/run_test.sh /onos ${@}
docker logs -f ${testerRunName} | tee ${DIR}/run.log

exitValTest=$(docker inspect ${testerRunName} --format='{{.State.ExitCode}}')
docker rm ${testerRunName}

echo " Stopping ${stratumRunName}..."
docker stop -t0 ${stratumRunName}

exit ${exitValTest}
