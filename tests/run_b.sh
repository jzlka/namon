#bin/sh

while true; do
	./udp_server 12345 &
	PID=$!
	sleep 8
	kill -2 $PID
done
