#!/bin/bash
#server="server/"
#client="client/"
port="0-65535"
#result="result/"
#seqinterval="100000"
#timeinterval="30"
#omit=""

dir=$1
sub=$2
#cnt=0
stat_str=""
for pcap in `find $dir |grep '.pcap$'`
do
    echo $pcap
    #let cnt++
    short_name=${pcap##*/}
    cnt=${short_name%.*}
    cnt=`echo $pcap | grep '/[0-9][0-9]*/' -o | grep '[0-9][0-9]*' -o`
    csvname=${cnt}${sub}.csv
    temp=tmp.${csvname}
    tshark -r "$pcap" -T fields  -o gui.column.format:"No.,%m,Time,%Yt,Source,%s,Destination,%d,Protocol,%p" -o tcp.relative_sequence_numbers:FALSE\
            -e _ws.col.No. -e _ws.col.Time -e _ws.col.Source -e _ws.col.Destination -e _ws.col.Protocol -e tcp.srcport -e tcp.dstport\
            -e tcp.ack -e tcp.seq -e tcp.flags.syn -e tcp.flags.ack -e tcp.flags.fin -e tcp.flags.reset\
            -e tcp.options.mptcp.rawdataseqno -e tcp.options.timestamp.tsval -e tcp.options.timestamp.tsecr -e tcp.window_size -e tcp.len -e tcp.hdr_len\
            -e tcp.analysis.lost_segment -e tcp.analysis.ack_rtt -e tcp.analysis.retransmission -e tcp.analysis.fast_retransmission -e tcp.analysis.spurious_retransmission -e tcp.analysis.bytes_in_flight\
            -E header=y -E separator=, -E quote=d\
            '(tcp && (ip.addr==10.4.112.0/24) && !tcp.port==22 && !http && !icmp)'\
            >$temp
    python polish.py $temp ${csvname} $port
    rm -f $temp
    stat_str="${stat_str}${csvname}\t\t\t${pcap}\n"
done
printf $stat_str >pcap.txt


