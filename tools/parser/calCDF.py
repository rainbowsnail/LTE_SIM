#########################################################################
# File Name: calCDF.py
# Author: Jing
# mail: jing.wang@pku.edu.cn
# Created Time:  5/24 13:25:49 2018
#########################################################################
import sys,os
if __name__ == '__main__':
    inputFile = sys.argv[1]
    outputFile = sys.argv[2]
    percentage = 0.0
    last_percemtage = 0.0
    
    output = open(outputFile, "w")
    with open(inputFile) as input:
        cnt = 0.0
        lines = input.readlines()
        lineNum=len(lines)
        for line in lines:
            cnt += 1
            percentage = cnt/lineNum * 100
            percentStr = '%.2f' % percentage
            if percentage-last_percemtage >= 1:
                output.write(line.strip() + ' '+ percentStr + '\n')
                last_percemtage = percentage

    output.close()


