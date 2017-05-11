#bin/sh

for i in {0..4}; do
	echo "Test #$i"
	./udp_server 12345 &
	PID=$!
	sleep 8
	kill -2 $PID
done
