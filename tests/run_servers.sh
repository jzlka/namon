#!/bin/bash


if [ $# -ne 1 ]; then
    echo "Wrong arguments"
    echo "./run_servers.sh <num> "
    exit 1
fi

ports=( $( seq 50000 `expr $1 + 50000`) )
for i in $(seq 0 $1); do
    ./udp_server ${ports[$i]} &
    serverPIDs+=($!)
done

echo Press any key to exit
read x

for i in "${serverPIDs[@]}"; do
    echo "$i killed"
    kill -s INT $i
done
