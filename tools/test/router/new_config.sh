#########################################################################
# File Name: config.sh
# Author: Jing
# mail: jing.wang@pku.edu.cn
# Created Time: Sun 26 Apr 2020 12:21:42 PM UTC
#########################################################################
#!/bin/bash
ethtool --offload veth6-4 gso off
ethtool --offload veth6-7 gro off
ethtool --offload veth6-4 gro off
ethtool --offload veth6-7 gso off
#route del -net 10.4.112.0 netmask 255.255.240.0 gw 0.0.0.0
#route del -net 10.4.96.0 netmask 255.255.240.0 gw 0.0.0.0
route -n
iptables  -I   FORWARD   -p   all   -s 10.106.107.2   -j   DROP
#iptables  -I   INPUT   -p   all   -s 10.106.107.2   -j   DROP
iptables  -I   FORWARD   -p   all   -s 10.102.104.1   -j   DROP
#iptables  -I   INPUT   -p   all   -s 10.106.107.2   -j   DROP
iptables -L
