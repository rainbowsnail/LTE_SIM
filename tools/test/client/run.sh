#########################################################################
# File Name: run.sh
# Author: Jing
# mail: jing.wang@pku.edu.cn
# Created Time: Thu 07 May 2020 04:23:02 AM UTC
#########################################################################
#!/bin/bash
ip netns exec ns2 bash autoclient.sh 350 1 veth2-4 ./result/client/
