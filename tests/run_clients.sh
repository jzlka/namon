#!/bin/bash


if [ $# -ne 5 ]; then
    echo "Wrong arguments"
    echo "./run_clients.sh <num> <remote_IP> <pps> <packet-size>"
    exit 1
fi

ports=( $( seq 50000 `expr $1 + 50000`) )
for i in $(seq 0 $1); do
    ./udp_client $2 ${ports[$i]} $3 $4 $5 &
    clientPIDs+=($!)
done

echo Press any key to exit
read x

for i in "${clientPIDs[@]}"; do
    echo "$i killed"
    kill -s INT $i
done
