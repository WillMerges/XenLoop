#!/bin/bash

TIME=120 # seconds
IP_DOMU="10.10.10.169"
IP_DOM0="10.10.10.1"

echo starting test on $HOSTNAME
echo remote domU IP: $IP_DOMU
echo remote dom0 IP: $IP_DOM0
echo
echo pinging remote domU
ping -4 -c 5 $IP_DOMU
echo
echo running ${TIME}s UDP/TCP tests for 5 repetitions
echo
echo

for R in {1..5}
do
    echo running round $R
    echo

    echo UDP round robin domU to domU, run \#${R}
    netperf -4 -H $IP_DOMU -l $TIME -t UDP_RR -- -o transaction_rate,mean_latency
    echo

    echo UDP round robin domU to dom0, run \#${R}
    netperf -4 -H $IP_DOM0 -l $TIME -t UDP_RR -- -o transaction_rate,mean_latency
    echo

    echo TCP round robin domU to domU, run \#${R}
    netperf -4 -H $IP_DOMU -l $TIME -t TCP_RR -- -o transaction_rate,mean_latency
    echo

    echo TCP round robin domU to dom0, run \#${R}
    netperf -4 -H $IP_DOM0 -l $TIME -t TCP_RR -- -o transaction_rate,mean_latency
    echo

    echo
    echo
done

echo done
