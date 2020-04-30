#########################################################################
# File Name: plot_n.sh
# Author: Jing
# mail: jing.wang@pku.edu.cn
# Created Time: Sun Apr 19 19:32:58 2020
#########################################################################
no=$1
simu=$2
flow=$3
for i in $(seq 1 $no);
do
mkdir -p $flow/$i
dstdir=$flow/$i
cp rtt.gp ./flow/$i/
cp thp.gp ./flow/$i/
cp ./dst/$i/${i}_thp_a.txt $dstdir/real_thp.txt
cp ./dst/$i/${i}_rtt_a.txt $dstdir/real_rtt.txt
cp ./$simu/$i/${i}_thp_a.txt $dstdir/simu_thp.txt
cp ./$simu/$i/${i}_rtt_a.txt $dstdir/simu_rtt.txt
cd $dstdir
gnuplot rtt.gp
gnuplot thp.gp
cd -
done
