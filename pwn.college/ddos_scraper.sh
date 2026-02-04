#!/bin/bash
for i in $(seq 1 2);
do
    echo $i
    python3 ddos.py 2> /dev/null &
done