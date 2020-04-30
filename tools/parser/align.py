#########################################################################
# File Name: align.py
# Author: Jing
# mail: jing.wang@pku.edu.cn
# Created Time: Sat Apr 18 21:24:47 2020
#########################################################################
import sys,os
if __name__ == "__main__":
    input_name = sys.argv[1]
    output_name = sys.argv[2]
    input_file = open(input_name, "r")
    output_file = open(output_name, "w")
    lines = input_file.readlines()
    start = float(lines[0].split(' ')[0])
    for line in lines:
        cur = float(line.split(' ')[0])
        #print(cur)
        output_file.write(str(cur-start+1) + ' ' + line.split(' ')[1] )
    input_file.close()
    output_file.close()

