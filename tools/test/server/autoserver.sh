#########################################################################
# File Name: autoserver.sh
# Author: Jing
# mail: jing.wang@pku.edu.cn
# Created Time: Thu 07 May 2020 04:18:09 AM UTC
#########################################################################
#!/bin/bash
total_flow=$1
repeat_num=$2
interface=$3
result_folder=$4
guard_duration=10
max_duration=150
mkdir -p $result_folder
kill `pidof tcpdump`
for i in $(seq 1 $total_flow);
do
	mkdir -p $result_folder/$i/
	mtu=`sed -n ${i}p mtu.txt`
	mtu=$((52+${mtu}))
	ifconfig veth7-6 mtu ${mtu}
	for j in $(seq 1 $repeat_num);
	do
		save_path=$result_folder/$i/$j.pcap
		tcpdump -i $interface -w $save_path &
		sleep 3
		./server &
		sleep 165
		#kill `pidof server`
		#sleep $max_duration
		sleep $guard_duration
		#kill `pidof tcpdump`
		#kill `pidof server`
	done
done
#kill `pidof server`
