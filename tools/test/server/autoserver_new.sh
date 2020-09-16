#!/bin/bash
total_flow=$1
repeat_num=$2
interface=$3
result_folder=$4
guard_duration=10
max_duration=150
mkdir -p $result_folder
kill `pidof tcpdump`
kill `pidof server`
for i in $(seq 1 $total_flow);
do
	mkdir -p $result_folder/$i/
	mtu=`sed -n ${i}p mtu.txt`
	#mtu=$((42+${mtu}))
	mtu=$((52+${mtu}))
	if [ $mtu -eq 1410 ];then
		mtu=1400
	fi
	ifconfig ens8 mtu ${mtu}
	for j in $(seq 1 $repeat_num);
	do
		save_path=$result_folder/$i/$j.pcap
		tcpdump -i $interface -s 200 -w $save_path &
		sleep 2
		./server &
		sleep 175
		#kill `pidof server`
		#sleep $max_duration
		sleep $guard_duration
		kill `pidof tcpdump`
		kill -9 `pidof server`
	done
done
#kill `pidof server`
