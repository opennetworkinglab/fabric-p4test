#!/usr/bin/env bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if [[ -z "${ONOS_ROOT}" ]]; then
    echo "ERROR: ONOS_ROOT env not defined"
    exit 1
fi

# Create image if it does not exist.
imageName=fabric-p4test
docker inspect ${imageName}:local > /dev/null || docker build . -t ${imageName}:local

runName=${imageName}-${RANDOM}

function ctrl_c() {
        echo " Stopping ${runName}..."
        docker stop ${runName}
}
trap ctrl_c INT

# Run and show log (also stored in run.log)
docker run --name ${runName} -d --privileged --rm \
    -v $DIR:/fabric-p4test \
    -v $ONOS_ROOT:/onos \
    fabric-p4test:local \
    bash /fabric-p4test/travis/run_test.sh /onos ${@}
docker logs -f ${runName} | tee ${DIR}/run.log

