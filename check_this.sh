#!/bin/bash

./target/debug/faux-mgs --interface eno1 start-host-flash-hash 0
while true; do
	./target/debug/faux-mgs --interface eno1 get-host-flash-hash 0
	if [ $? -eq 0 ]; then
		exit 0
	fi
	sleep 1
done
