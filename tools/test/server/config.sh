#########################################################################
# File Name: config.sh
# Author: Jing
# mail: jing.wang@pku.edu.cn
# Created Time: Thu 07 May 2020 04:21:13 AM UTC
#########################################################################
#!/bin/bash
ethtool --offload ens8 gso off
ethtool --offload ens8 gro off
