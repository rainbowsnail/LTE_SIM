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
ifconfig ens8 mtu 1400
ifconfig ens7 mtu 1400
