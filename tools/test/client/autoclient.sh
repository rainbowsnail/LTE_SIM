#########################################################################
# File Name: autoclient.sh
# Author: Jing
# mail: jing.wang@pku.edu.cn
# Created Time: Thu 07 May 2020 04:22:37 AM UTC
#########################################################################
#!/bin/bash
total_flow=$1
repeat_num=$2
interface=$3
result_folder=$4
max_duration=150
guard_duration=10
mkdir -p $result_folder
kill `pidof tcpdump`
for i in $(seq 1 $total_flow);
do
	mkdir -p $result_folder/$i/
	for j in $(seq 1 $repear_num);
	do
		save_path=$result_folder/$i/$j.pcap
		tcpdump -i $interface -w $save_path &
		sleep 3
		./client &
		sleep 165
		kill `pidof client`
		sleep $guard_duration
		kill `pidof tcpdump`
	done
done
#kill `pidof client`
