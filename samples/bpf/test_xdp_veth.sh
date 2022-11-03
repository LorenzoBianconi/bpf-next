#!/bin/bash

DIR=/home/lorenzo/workspace/bpf-next/samples/bpf
DURATION=10

clean_up()
{
	kill $(pidof iperf3) 2> /dev/null
	kill $(pidof xdp_prog) 2> /dev/null
	ip -n remote link del v1
	ip netns del remote
}

setup()
{
	ip netns add remote

	sysctl -w net.ipv4.ip_forward=1
	ip netns exec remote sysctl -w net.ipv4.ip_forward=1

	ip link add v0 type veth peer name v1 netns remote
	ip link set v0 address 00:11:22:33:11:55
	ip link set v0 up
	ip addr add 192.168.1.1/24 dev v0
	ethtool -K v0 tso off
	ethtool -K v0 gso off
	ethtool -K v0 gro on
	ethtool -K v0 tx-checksumming off
	ethtool -K v0 rx-checksumming off
	ip -n remote link set v1 address 00:11:22:33:22:55
	ip -n remote link set v1 up
	ip -n remote addr add 192.168.1.2/24 dev v1
	ip netns exec remote ethtool -K v1 tso off
	ip netns exec remote ethtool -K v1 gso off
	ip netns exec remote ethtool -K v1 gro on
	ip netns exec remote ethtool -K v1 tx-checksumming off
	ip netns exec remote ethtool -K v1 rx-checksumming off

	$DIR/xdp_prog v0 &
	# enable snat (we need it to enable conntracking
	#ip netns exec ns2 iptables -t nat -A POSTROUTING -s 192.168.100.0/24 -o v11 -j SNAT --to-source 192.168.200.2
	#ip netns exec ns2 sysctl -w net.netfilter.nf_conntrack_tcp_be_liberal=1

	ip netns exec remote sysctl -w net.netfilter.nf_conntrack_tcp_be_liberal=1
	sysctl -w net.netfilter.nf_conntrack_tcp_be_liberal=1
}

run_test()
{
	iperf3 -s >/dev/null &
	sleep 1
	ip netns exec remote iperf3 -c 192.168.1.1 -t $DURATION -i 5

	cat /sys/kernel/debug/tracing/trace_pipe
}

clean_up
setup
run_test
