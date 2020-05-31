#########################################################################
# File Name: config.sh
# Author: Jing
# mail: jing.wang@pku.edu.cn
# Created Time: Sun 26 Apr 2020 12:21:42 PM UTC
#########################################################################
#!/bin/bash
ethtool --offload ens8 gso off
ethtool --offload ens8 gro off
ethtool --offload ens7 gro off
ethtool --offload ens7 gso off
#ifconfig ens8 mtu 1400
#ifconfig ens7 mtu 1400
#route del -net 10.4.112.0 netmask 255.255.240.0 gw 0.0.0.0
#route del -net 10.4.96.0 netmask 255.255.240.0 gw 0.0.0.0
route -n
iptables  -I   INPUT   -p   all   -s 10.4.112.4   -j   DROP
iptables  -I   INPUT   -p   all   -s 10.4.96.4   -j   DROP
iptables -L
