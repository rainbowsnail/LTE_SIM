sudo ip netns exec ns6 bash new_config.sh
sudo ip netns exec ns2 ethtool -K veth2-4 tx-checksum-ip-generic off
sudo ip netns exec ns7 ethtool -K veth7-6 tx-checksum-ip-generic off
sudo ip netns exec ns6 ethtool -K veth6-4 tx-checksum-ip-generic off
sudo ip netns exec ns6 ethtool -K veth6-7 tx-checksum-ip-generic off
