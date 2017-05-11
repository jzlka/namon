#/bin/sh

tests=( 64 128 256 512 1024 1280 1518 )

for pktSize in "${tests[@]}"; do
	echo
	echo "*** packet size: $pktSize"
	for i in {0..4}; do
		echo "Test #$i"
		./udp_client 10.10.10.110 12345 1 $pktSize &
		PID=$!
		sleep  8
		kill -2 $PID
	done
done

