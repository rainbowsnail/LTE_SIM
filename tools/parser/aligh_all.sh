#########################################################################
# File Name: aligh_all.sh
# Author: Jing
# mail: jing.wang@pku.edu.cn
# Created Time: Sat Apr 18 21:45:37 2020
#########################################################################
no=$1
dir=$2
for i in $(seq 1 $no);
do
python2 align.py $dir/$i/${i}_thp.txt $dir/$i/${i}_thp_a.txt
python2 align.py $dir/$i/${i}_rtt.txt $dir/$i/${i}_rtt_a.txt
python2 align.py $dir/$i/${i}_retx.txt $dir/$i/${i}_retx_a.txt
python2 align.py $dir/$i/${i}_loss.txt $dir/$i/${i}_loss_a.txt
done
