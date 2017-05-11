#!/bin/bash
#   @file       run_server.sh
#   @brief      Brief description
#   @author     Jozef Zuzelka <xzuzel00@stud.fit.vutbr.cz>
#   @date
#    - Created: 10.05.2017 14:44
#    - Edited:  10.05.2017 16:35
#   @par        SHELL: GNU bash, version 3.2.57(1)-release (x86_64-apple-darwin16)



if [ $# -ne 1 ]; then
    echo "Wrong arguments"
    echo "./run_server.sh <num> "
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
