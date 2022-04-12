#!/bin/bash

DIR=/home/lorenzo/workspace/bpf-next/samples/bpf
DURATION=30

clean_up()
{
	rm -f /tmp/*.pcap
	kill $(pidof iperf3) 2> /dev/null
	kill $(pidof xdp_router_ipv4) 2> /dev/null
	for i in $(seq 3); do
		ip -n ns$i link del v${i}0
		ip -n ns$((i+1)) link del v${i}1
	done 2> /dev/null
	for i in $(seq 4); do
		ip netns del ns$i
	done 2> /dev/null
}

setup()
{
	for i in $(seq 4); do
		ip netns add ns$i
		ip netns exec ns$i sysctl -w net.ipv4.ip_forward=1
	done >/dev/null
	for i in $(seq 3); do
		ip link add v${i}0 netns ns$i type veth \
			peer name v${i}1 netns ns$((i+1))
		ip -n ns$i link set v${i}0 address 00:$i$i:22:33:$i$i:55
		ip -n ns$i link set v${i}0 up
		ip -n ns$i addr add 192.168.$i.1/24 dev v${i}0
		ip netns exec ns$i ethtool -K v${i}0 tso off
		ip netns exec ns$i ethtool -K v${i}0 gso off
		ip netns exec ns$i ethtool -K v${i}0 gro on
		ip netns exec ns$i ethtool -K v${i}0 tx-checksumming off
		ip netns exec ns$i ethtool -K v${i}0 rx-checksumming off
		ip -n ns$((i+1)) link set v${i}1 address 00:$i$i:22:33:$((i+1))$((i+1)):55
		ip -n ns$((i+1)) link set v${i}1 up
		ip -n ns$((i+1)) addr add 192.168.$i.2/24 dev v${i}1
		ip netns exec ns$((i+1)) ethtool -K v${i}1 tso off
		ip netns exec ns$((i+1)) ethtool -K v${i}1 gso off
		ip netns exec ns$((i+1)) ethtool -K v${i}1 gro on
		ip netns exec ns$((i+1)) ethtool -K v${i}1 tx-checksumming off
		ip netns exec ns$((i+1)) ethtool -K v${i}1 rx-checksumming off
	done > /dev/null

	# setup static routes
	ip -n ns1 route add default via 192.168.1.2
	ip -n ns2 route add 192.168.3.0/24 via 192.168.2.2
	ip -n ns3 route add 192.168.1.0/24 via 192.168.2.1
	ip -n ns4 route add default via 192.168.3.1
	# xdp fib lookup
	ip netns exec ns2 $DIR/xdp_router_ipv4 -i 1 v11 >/dev/null &
	ip netns exec ns2 $DIR/xdp_router_ipv4 -i 1 v20 >/dev/null &
	# enable snat (we need it to enable conntracking
	ip netns exec ns2 iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o v11 -j SNAT --to-source 192.168.1.2
	ip netns exec ns2 sysctl -w net.netfilter.nf_conntrack_tcp_be_liberal=1
}

run_tcpdump()
{
	rm -f /tmp/v10.pcap /tmp/v11.pcap \
	      /tmp/v31.pcap /tmp/v21.pcap \
	      /tmp/v30.pcap /tmp/v20.pcap 

	ip netns exec ns1 tcpdump -nneei v10 -s0 -w /tmp/v10.pcap &
	ip netns exec ns1 tcpdump -nneei v10 -s0 -w /tmp/v11.pcap &
	ip netns exec ns4 tcpdump -nneei v31 -s0 -w /tmp/v31.pcap &
	ip netns exec ns3 tcpdump -nneei v21 -s0 -w /tmp/v21.pcap &
	ip netns exec ns3 tcpdump -nneei v30 -s0 -w /tmp/v30.pcap &
	ip netns exec ns2 tcpdump -nneei v20 -s0 -w /tmp/v20.pcap &
}

run_test()
{
	#run_tcpdump >/dev/null
	ip netns exec ns4 iperf3 -s >/dev/null &
	sleep 1
	#while sleep 1; do
	#	ip netns exec ns2 ethtool -S v11 | grep xdp_redi
	#	ip netns exec ns2 ethtool -S v20 | grep xdp_redi
	#	ip netns exec ns2 conntrack -L
	#done &
	ip netns exec ns1 iperf3 -c 192.168.3.2 -t $DURATION -i 2

	#cat /sys/kernel/debug/tracing/trace_pipe
	killall tcpdump >/dev/null
}

clean_up
setup
run_test
