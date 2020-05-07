#########################################################################
# File Name: splot_all.sh
# Author: Jing
# mail: jing.wang@pku.edu.cn
# Created Time: Sun Apr 19 19:26:24 2020
#########################################################################
dir=$1
no=$2
plot_dir=$3
for i in $(seq 1 $no);
do
	mkdir -p ./$plot_dir/$i
	python splot.py -s ./$dir -t ./$plot_dir/$i -n $i
done
