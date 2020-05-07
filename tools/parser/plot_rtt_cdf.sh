#########################################################################
# File Name: plot_rtt_cdf.sh
# Author: Jing
# mail: jing.wang@pku.edu.cn
# Created Time: Tue Apr 28 19:44:20 2020
#########################################################################
cat `find simu | grep rtt.txt` | awk '{print $2}' |sort -g > simu_rtt.sort
cat `find simu | grep thp.txt` | awk '{print $2}' |sort -g > simu_thp.sort
python calCDF.py simu_rtt.sort simu_rtt.cdf
python calCDF.py simu_thp.sort simu_thp.cdf

gnuplot rtt_CDF.gp 
gnuplot thp_CDF.gp 
