#########################################################################
# File Name: new_autoclient.sh
# Author: Jing
# mail: jing.wang@pku.edu.cn
# Created Time: Wed 16 Sep 2020 07:29:16 AM UTC
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
kill `pidof client`
for i in $(seq 1 $total_flow);
do
	mkdir -p $result_folder/$i/
	#mtu=`sed -n ${i}p mtu.txt`
	#mtu=$((52+${mtu}))
	#ifconfig ens7 mtu ${mtu}
	for j in $(seq 1 $repear_num);
	do
		save_path=$result_folder/$i/$j.pcap
		sleep 5
		tcpdump -i $interface -s 200 -w $save_path &
		sleep 2
		./client &
		sleep 170
		kill `pidof client`
		kill `pidof tcpdump`
		sleep $guard_duration
	done
done
#kill `pidof client`
