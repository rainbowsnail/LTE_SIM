import os
import sys
import csv
import time

server="10.4.112"
client="10.4.96"
#server="222.29.98"

def transfer(st):
    p=st.find('.')
    time_str=st[:p]
    x=float(time.mktime(time.strptime(time_str,"%Y-%m-%d %H:%M:%S")))
    y=float(st[p:])
    return x+y

def parse(st):
    vis=[0 for i in xrange(0,65536,1)]
    conds=st.split(',')
    for cond in conds:
        p=cond.find('-')
        if p!=-1:
            l=int(cond[:p])
            r=int(cond[p+1:])
            for i in xrange(l,r+1,1):
                vis[i]=1
        else:
            vis[int(cond)]=1
    return vis

vis=parse(sys.argv[3])

file1=sys.argv[1]
fin=open(file1,"r")
reader=csv.reader(fin)
file2=sys.argv[2]
fout=open(file2,"w")
writer=csv.writer(fout,lineterminator="\n")
i=0; cnt=0
for row in reader:
    if i>0:
        if row[2].find(server)!=-1:
            port=int(row[5])
        elif row[2].find(client)!=-1:
            port=int(row[5])
        else:
            port=int(row[6])
        if vis[port]==0:
            continue
        cnt+=1
        row[0]=cnt
        line=row[:2]+[transfer(row[1])]+row[2:]
    else:
        line=row[:2]+["timestamp"]+row[2:]
    i+=1
    writer.writerow(line)
fin.close()
