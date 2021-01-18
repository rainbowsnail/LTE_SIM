folder=~/MoreData/emulatedM3Tests/tools/csv/1/
no=$1
sudo ip netns exec ns6 ./emulator --server $folder/ff${no}s.csv --client $folder/ff${no}c.csv --sif veth6-7 --cif veth6-4 --tcip 10.102.104.1 --tsip 10.106.107.2
#sudo ip netns exec ns6 ./emulator --server ./trace.new/1s.csv --client ./trace.new/1c.csv --sif veth6-7 --cif veth6-4 --tcip 10.102.104.1 --tsip 10.106.107.2
#sudo ip netns exec ns6 ./simulator --no 1 --sif veth6-7 --cif veth6-4 
#sudo ip netns exec ns6 ./simulator --no 1 --sif veth6-7 --cif veth6-4 --sip 10.106.107.2 --tsip 10.106.107.2 --tcip 10.102.104.1
