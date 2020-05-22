#!/usr/bin/env bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if [[ -z "${ONOS_ROOT}" ]]; then
    echo "ERROR: ONOS_ROOT env not defined"
    exit 1
fi

# For now let's make sure runs are reproducible by using a specific version of mn-stratum.
# TODO: move this to .travis.yml and run tests on both latest and a known stable version
MN_STRATUM_SHA="sha256:6cd25463f4b1589e1396fefe73583da499acfdfe8903f3d2b8e4180adc996ee3"

radomNumber=${RANDOM}

# Stratum BMv2
stratumImageName=opennetworking/mn-stratum:latest@${MN_STRATUM_SHA}
stratumRunName=stratum-bmv2-${radomNumber}

# PTF Tester
testerImageName=${PTFTEST_IMAGE:-onosproject/fabric-p4test:latest}
testerRunName=fabric-p4test-${radomNumber}

exitValTest=1

function ctrl_c() {
        echo "*** Stopping ${testerRunName}..."
        docker stop -t0 ${testerRunName} > /dev/null
        exitValTest=$(docker inspect ${testerRunName} --format='{{.State.ExitCode}}')
        docker rm ${testerRunName} > /dev/null

        echo "*** Stopping ${stratumRunName}..."
        docker stop -t0 ${stratumRunName} > /dev/null
        exit "${exitValTest}"
}
trap ctrl_c EXIT

# Run stratum-bmv2
echo "*** Starting ${stratumRunName}..."
docker run --name ${stratumRunName} -d --privileged --rm \
    --entrypoint "/fabric-p4test/run/bmv2/start_stratum_bmv2.sh" \
    -v "${DIR}":/fabric-p4test \
    ${stratumImageName}
sleep 2

# Run and show log (also stored in run.log)
echo "*** Starting ${testerRunName}..."
docker run --name ${testerRunName} -d --privileged \
    --network "container:${stratumRunName}" \
    -v "${DIR}":/fabric-p4test \
    -v "${ONOS_ROOT}":/onos \
    "${testerImageName}" \
    bash /fabric-p4test/run/bmv2/run_test.sh /onos ${@}
docker logs -f ${testerRunName} | tee "${DIR}"/run.log
