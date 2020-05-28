#!/bin/bash

echo 128 > /proc/sys/vm/nr_hugepages
mkdir /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

stratum_bf -flagfile=/fabric-p4test/run/tm/stratum.flags &> /fabric-p4test/run/tm/log/stratum_bf.log
