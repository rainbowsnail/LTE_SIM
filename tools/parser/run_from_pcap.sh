#########################################################################
# File Name: run_from_pcap.sh
# Author: Jing
# mail: jing.wang@pku.edu.cn
# Created Time: Tue Apr 28 17:10:52 2020
#########################################################################
dir=$1
no=$2
parse_dir=$3
plot_dir=$4
bash parser.sh ./$dir/server s
bash parser.sh ./$dir/client c
mv *s.csv ./$dir/
mv *c.csv ./$dir/
bash splot_all.sh $dir $no $parse_dir
bash aligh_all.sh $no ./$parse_dir/
bash plot_n.sh $no $parse_dir $plot_dir
