#!/bin/bash
for i in $(seq 1 50000);
do
    echo $i
    nc 10.0.0.2 31337 &
done