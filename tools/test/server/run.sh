#########################################################################
# File Name: run.sh
# Author: Jing
# mail: jing.wang@pku.edu.cn
# Created Time: Thu 07 May 2020 04:20:43 AM UTC
#########################################################################
#!/bin/bash
ip netns exec ns7 bash autoserver.sh 350 1 veth7-6 ./result/server/
