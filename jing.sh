sudo ip netns exec ns6 ./simulator --server ./trace/1s.csv --client ./trace/1c.csv --sif veth6-7 --cif veth6-4 --tcip 10.102.104.1 --tsip 10.106.107.2
#sudo ip netns exec ns6 ./simulator --no 1 --sif veth6-7 --cif veth6-4 
#sudo ip netns exec ns6 ./simulator --no 1 --sif veth6-7 --cif veth6-4 --sip 10.106.107.2 --tsip 10.106.107.2 --tcip 10.102.104.1
