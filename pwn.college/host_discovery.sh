#!/bin/bash

net="10.0.0."
for i in $(seq 0 255)
do
    host=$net$i
    echo "Pinging $host..."
    if ping -c2 $host > /dev/null; then
        echo "$host is up"
    fi
done
