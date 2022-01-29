// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2017 Cavium, Inc.
 */
#include <linux/bpf.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include "bpf_util.h"
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <libgen.h>
#include <getopt.h>
#include <stdbool.h>

#include "xdp_sample_user.h"
#include "xdp_router_ipv4.skel.h"

static const char *__doc__ =
"XDP IPv4 router implementation\n"
"Usage: xdp_router_ipv4 <IFINDEX_0> <IFINDEX_1> ... <IFINDEX_n>\n";

DEFINE_SAMPLE_INIT(xdp_router_ipv4);

static int mask = SAMPLE_RX_CNT | SAMPLE_REDIRECT_ERR_MAP_CNT |
		  SAMPLE_EXCEPTION_CNT | SAMPLE_DEVMAP_XMIT_CNT_MULTI;

static const struct option long_options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "skb-mode", no_argument, NULL, 'S' },
	{ "force", no_argument, NULL, 'F' },
	{ "interval", required_argument, NULL, 'i' },
	{ "verbose", no_argument, NULL, 'v' },
	{}
};

static char buf[8192];

static void get_route_table(struct xdp_router_ipv4 *skel, int rtm_family);

static void usage(char *argv[], const struct option *long_options,
		  const char *doc, int mask, bool error)
{
	sample_usage(argv, long_options, doc, mask, error);
}

/* Get the mac address of the interface given interface name */
static __be64 getmac(char *iface)
{
	struct ifreq ifr;
	__be64 mac = 0;
	int fd, i;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		fprintf(stderr, "ioctl failed leaving\n");
		return -1;
	}
	for (i = 0; i < 6 ; i++)
		*((__u8 *)&mac + i) = (__u8)ifr.ifr_hwaddr.sa_data[i];

	close(fd);

	return mac;
}

static int recv_msg(struct sockaddr_nl sock_addr, int sock)
{
	char *buf_ptr = buf;
	struct nlmsghdr *nh;
	int len, nll = 0;

	while (1) {
		len = recv(sock, buf_ptr, sizeof(buf) - nll, 0);
		if (len < 0)
			return len;

		nh = (struct nlmsghdr *)buf_ptr;

		if (nh->nlmsg_type == NLMSG_DONE)
			break;

		buf_ptr += len;
		nll += len;

		if ((sock_addr.nl_groups & RTMGRP_NEIGH) == RTMGRP_NEIGH)
			break;

		if ((sock_addr.nl_groups & RTMGRP_IPV4_ROUTE) == RTMGRP_IPV4_ROUTE)
			break;
	}

	return nll;
}

/* Function to parse the route entry returned by netlink
 * Updates the route entry related map entries
 */
static void read_route(struct xdp_router_ipv4 *skel,
		       struct nlmsghdr *nh, int nll)
{
	char dsts[24], gws[24], ifs[16], dsts_len[24], metrics[24];
	struct bpf_lpm_trie_key *prefix_key;
	struct rtattr *rt_attr;
	int i, rtl, rtm_family;
	struct rtmsg *rt_msg;
	struct route_table {
		int  dst_len, iface, metric;
		char *iface_name;
		__be32 dst, gw;
		__be64 mac;
	} route;
	struct arp_table {
		__be64 mac;
		__be32 dst;
	};
	struct direct_map {
		struct arp_table arp;
		int ifindex;
		__be64 mac;
	} direct_entry;

	memset(&route, 0, sizeof(route));
	for (; NLMSG_OK(nh, nll); nh = NLMSG_NEXT(nh, nll)) {
		rt_msg = (struct rtmsg *)NLMSG_DATA(nh);
		rtm_family = rt_msg->rtm_family;
		if (rtm_family == AF_INET)
			if (rt_msg->rtm_table != RT_TABLE_MAIN)
				continue;
		rt_attr = (struct rtattr *)RTM_RTA(rt_msg);
		rtl = RTM_PAYLOAD(nh);

		for (; RTA_OK(rt_attr, rtl); rt_attr = RTA_NEXT(rt_attr, rtl)) {
			switch (rt_attr->rta_type) {
			case NDA_DST:
				sprintf(dsts, "%u",
					(*((__be32 *)RTA_DATA(rt_attr))));
				break;
			case RTA_GATEWAY:
				sprintf(gws, "%u",
					*((__be32 *)RTA_DATA(rt_attr)));
				break;
			case RTA_OIF:
				sprintf(ifs, "%u",
					*((int *)RTA_DATA(rt_attr)));
				break;
			case RTA_METRICS:
				sprintf(metrics, "%u",
					*((int *)RTA_DATA(rt_attr)));
			default:
				break;
			}
		}
		sprintf(dsts_len, "%d", rt_msg->rtm_dst_len);
		route.dst = atoi(dsts);
		route.dst_len = atoi(dsts_len);
		route.gw = atoi(gws);
		route.iface = atoi(ifs);
		route.metric = atoi(metrics);
		route.iface_name = alloca(sizeof(char *) * IFNAMSIZ);
		route.iface_name = if_indextoname(route.iface, route.iface_name);
		route.mac = getmac(route.iface_name);

		assert(!bpf_map_update_elem(bpf_map__fd(skel->maps.tx_port),
					    &route.iface, &route.iface, 0));
		if (rtm_family == AF_INET) {
			struct trie_value {
				__u8 prefix[4];
				__be64 value;
				int ifindex;
				int metric;
				__be32 gw;
			} *prefix_value;

			prefix_key = alloca(sizeof(*prefix_key) + 3);
			prefix_value = alloca(sizeof(*prefix_value));

			prefix_key->prefixlen = 32;
			prefix_key->prefixlen = route.dst_len;
			direct_entry.mac = route.mac & 0xffffffffffff;
			direct_entry.ifindex = route.iface;
			direct_entry.arp.mac = 0;
			direct_entry.arp.dst = 0;
			if (route.dst_len == 32) {
				if (nh->nlmsg_type == RTM_DELROUTE) {
					assert(!bpf_map_delete_elem(
						bpf_map__fd(skel->maps.exact_match),
						&route.dst));
				} else {
					if (!bpf_map_lookup_elem(
						bpf_map__fd(skel->maps.arp_table),
						&route.dst, &direct_entry.arp.mac))
						direct_entry.arp.dst = route.dst;
					assert(!bpf_map_update_elem(
						bpf_map__fd(skel->maps.exact_match),
						&route.dst, &direct_entry, 0));
				}
			}

			for (i = 0; i < 4; i++)
				prefix_key->data[i] = (route.dst >> i * 8) & 0xff;

			if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.lpm_map),
						prefix_key, prefix_value) < 0) {
				for (i = 0; i < 4; i++)
					prefix_value->prefix[i] = prefix_key->data[i];
				prefix_value->value = route.mac & 0xffffffffffff;
				prefix_value->ifindex = route.iface;
				prefix_value->gw = route.gw;
				prefix_value->metric = route.metric;

				assert(!bpf_map_update_elem(
					bpf_map__fd(skel->maps.lpm_map),
					prefix_key, prefix_value, 0));
			} else {
				if (nh->nlmsg_type == RTM_DELROUTE) {
					assert(!bpf_map_delete_elem(
						bpf_map__fd(skel->maps.lpm_map),
						prefix_key));
					/* Rereading the route table to check if
					 * there is an entry with the same
					 * prefix but a different metric as the
					 * deleted enty.
					 */
					get_route_table(skel, AF_INET);
				} else if (prefix_key->data[0] ==
					   prefix_value->prefix[0] &&
					   prefix_key->data[1] ==
					   prefix_value->prefix[1] &&
					   prefix_key->data[2] ==
					   prefix_value->prefix[2] &&
					   prefix_key->data[3] ==
					   prefix_value->prefix[3] &&
					   route.metric >= prefix_value->metric) {
					continue;
				} else {
					for (i = 0; i < 4; i++)
						prefix_value->prefix[i] =
							prefix_key->data[i];
					prefix_value->value =
						route.mac & 0xffffffffffff;
					prefix_value->ifindex = route.iface;
					prefix_value->gw = route.gw;
					prefix_value->metric = route.metric;
					assert(!bpf_map_update_elem(
						bpf_map__fd(skel->maps.lpm_map),
						prefix_key, prefix_value, 0));
				}
			}
		}

		memset(&route, 0, sizeof(route));
		memset(dsts, 0, sizeof(dsts));
		memset(dsts_len, 0, sizeof(dsts_len));
		memset(gws, 0, sizeof(gws));
		memset(ifs, 0, sizeof(ifs));
		memset(&route, 0, sizeof(route));
	}
}

/* Function to read the existing route table  when the process is launched */
static void get_route_table(struct xdp_router_ipv4 *skel, int rtm_family)
{
	struct sockaddr_nl sa;
	struct nlmsghdr *nh;
	int sock, seq = 0;
	struct msghdr msg;
	struct iovec iov;
	int ret = 0;
	int nll;
	struct {
		struct nlmsghdr nl;
		struct rtmsg rt;
		char buf[8192];
	} req;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		fprintf(stderr, "open netlink socket: %s\n", strerror(errno));
		return;
	}

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		fprintf(stderr, "bind to netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	memset(&req, 0, sizeof(req));
	req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nl.nlmsg_type = RTM_GETROUTE;
	req.rt.rtm_family = rtm_family;
	req.rt.rtm_table = RT_TABLE_MAIN;
	req.nl.nlmsg_pid = 0;
	req.nl.nlmsg_seq = ++seq;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = (void *)&req.nl;
	iov.iov_len = req.nl.nlmsg_len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ret = sendmsg(sock, &msg, 0);
	if (ret < 0) {
		fprintf(stderr, "send to netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	memset(buf, 0, sizeof(buf));
	nll = recv_msg(sa, sock);
	if (nll < 0) {
		fprintf(stderr, "recv from netlink: %s\n", strerror(nll));
		goto cleanup;
	}

	nh = (struct nlmsghdr *)buf;
	read_route(skel, nh, nll);

cleanup:
	close(sock);
}

/* Function to parse the arp entry returned by netlink
 * Updates the arp entry related map entries
 */
static void read_arp(struct xdp_router_ipv4 *skel,
		     struct nlmsghdr *nh, int nll)
{
	struct rtattr *rt_attr;
	char dsts[24], mac[24];
	struct ndmsg *rt_msg;
	int rtl, ndm_family;
	struct arp_table {
		__be64 mac;
		__be32 dst;
	} arp_entry;
	struct direct_map {
		struct arp_table arp;
		int ifindex;
		__be64 mac;
	} direct_entry;

	for (; NLMSG_OK(nh, nll); nh = NLMSG_NEXT(nh, nll)) {
		rt_msg = (struct ndmsg *)NLMSG_DATA(nh);
		rt_attr = (struct rtattr *)RTM_RTA(rt_msg);
		ndm_family = rt_msg->ndm_family;
		rtl = RTM_PAYLOAD(nh);

		for (; RTA_OK(rt_attr, rtl); rt_attr = RTA_NEXT(rt_attr, rtl)) {
			switch (rt_attr->rta_type) {
			case NDA_DST:
				sprintf(dsts, "%u",
					*((__be32 *)RTA_DATA(rt_attr)));
				break;
			case NDA_LLADDR:
				sprintf(mac, "%lld",
					*((__be64 *)RTA_DATA(rt_attr)));
				break;
			default:
				break;
			}
		}

		arp_entry.dst = atoi(dsts);
		arp_entry.mac = atol(mac);

		if (ndm_family == AF_INET) {
			if (!bpf_map_lookup_elem(
			     bpf_map__fd(skel->maps.exact_match),
			     &arp_entry.dst, &direct_entry)) {
				if (nh->nlmsg_type == RTM_DELNEIGH) {
					direct_entry.arp.dst = 0;
					direct_entry.arp.mac = 0;
				} else if (nh->nlmsg_type == RTM_NEWNEIGH) {
					direct_entry.arp.dst = arp_entry.dst;
					direct_entry.arp.mac = arp_entry.mac;
				}
				assert(!bpf_map_update_elem(
					bpf_map__fd(skel->maps.exact_match),
					&arp_entry.dst, &direct_entry, 0));
				memset(&direct_entry, 0, sizeof(direct_entry));
			}

			if (nh->nlmsg_type == RTM_DELNEIGH)
				assert(!bpf_map_delete_elem(
					bpf_map__fd(skel->maps.arp_table),
					&arp_entry.dst));
			else if (nh->nlmsg_type == RTM_NEWNEIGH)
				assert(!bpf_map_update_elem(
					bpf_map__fd(skel->maps.arp_table),
					&arp_entry.dst, &arp_entry.mac, 0));
		}

		memset(&arp_entry, 0, sizeof(arp_entry));
		memset(dsts, 0, sizeof(dsts));
	}
}

/* Function to read the existing arp table  when the process is launched*/
static void get_arp_table(struct xdp_router_ipv4 *skel, int rtm_family)
{
	int nll, sock, seq = 0;
	struct sockaddr_nl sa;
	struct nlmsghdr *nh;
	struct msghdr msg;
	struct iovec iov;
	struct {
		struct nlmsghdr nl;
		struct ndmsg rt;
		char buf[8192];
	} req;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		fprintf(stderr, "open netlink socket: %s\n", strerror(errno));
		return;
	}

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		fprintf(stderr, "bind to netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	memset(&req, 0, sizeof(req));
	req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nl.nlmsg_type = RTM_GETNEIGH;
	req.rt.ndm_state = NUD_REACHABLE;
	req.rt.ndm_family = rtm_family;
	req.nl.nlmsg_pid = 0;
	req.nl.nlmsg_seq = ++seq;

	memset(&msg, 0, sizeof(msg));
	iov.iov_base = (void *)&req.nl;
	iov.iov_len = req.nl.nlmsg_len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(sock, &msg, 0) < 0) {
		fprintf(stderr, "send to netlink: %s\n", strerror(errno));
		goto cleanup;
	}

	memset(buf, 0, sizeof(buf));
	nll = recv_msg(sa, sock);
	if (nll < 0) {
		fprintf(stderr, "recv from netlink: %s\n", strerror(nll));
		goto cleanup;
	}

	nh = (struct nlmsghdr *)buf;
	read_arp(skel, nh, nll);

cleanup:
	close(sock);
}

/* Function to keep track and update changes in route and arp table
 * Give regular statistics of packets forwarded
 */
static void monitor_route(void *ctx)
{
	struct xdp_router_ipv4 *skel = ctx;
	struct pollfd fds_route, fds_arp;
	struct sockaddr_nl la, lr;
	int nll, sock, arp_sock;
	struct nlmsghdr *nh;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		fprintf(stderr, "open netlink socket: %s\n", strerror(errno));
		return;
	}

	fcntl(sock, F_SETFL, O_NONBLOCK);
	memset(&lr, 0, sizeof(lr));
	lr.nl_family = AF_NETLINK;
	lr.nl_groups = RTMGRP_IPV6_ROUTE | RTMGRP_IPV4_ROUTE | RTMGRP_NOTIFY;
	if (bind(sock, (struct sockaddr *)&lr, sizeof(lr)) < 0) {
		fprintf(stderr, "bind to netlink: %s\n", strerror(errno));
		goto cleanup_sock;
	}

	fds_route.fd = sock;
	fds_route.events = POLL_IN;

	arp_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (arp_sock < 0) {
		fprintf(stderr, "open netlink socket: %s\n", strerror(errno));
		goto cleanup_sock;
	}

	fcntl(arp_sock, F_SETFL, O_NONBLOCK);
	memset(&la, 0, sizeof(la));
	la.nl_family = AF_NETLINK;
	la.nl_groups = RTMGRP_NEIGH | RTMGRP_NOTIFY;
	if (bind(arp_sock, (struct sockaddr *)&la, sizeof(la)) < 0) {
		fprintf(stderr, "bind to netlink: %s\n", strerror(errno));
		goto cleanup_arp_sock;
	}
	fds_arp.fd = arp_sock;
	fds_arp.events = POLL_IN;

	memset(buf, 0, sizeof(buf));
	if (poll(&fds_route, 1, 3) == POLL_IN) {
		nll = recv_msg(lr, sock);
		if (nll < 0) {
			fprintf(stderr, "recv from netlink: %s\n",
				strerror(nll));
			goto cleanup_arp_sock;
		}

		nh = (struct nlmsghdr *)buf;
		read_route(skel, nh, nll);
	}

	memset(buf, 0, sizeof(buf));
	if (poll(&fds_arp, 1, 3) == POLL_IN) {
		nll = recv_msg(la, arp_sock);
		if (nll < 0) {
			fprintf(stderr, "recv from netlink: %s\n",
				strerror(nll));
			goto cleanup_arp_sock;
		}

		nh = (struct nlmsghdr *)buf;
		read_arp(skel, nh, nll);
	}

cleanup_arp_sock:
	close(arp_sock);
cleanup_sock:
	close(sock);
}

int main(int argc, char **argv)
{
	bool generic = false, force = false;
	struct xdp_router_ipv4 *skel;
	int ret = EXIT_FAIL_OPTION;
	char **ifname_list = argv + 1;
	int i, num_ifindex = argc - 1;
	unsigned long interval = 2;
	int opt, longindex = 0;

	skel = xdp_router_ipv4__open();
	if (!skel) {
		fprintf(stderr, "Failed to xdp_router_ipv4__open: %s\n",
			strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end;
	}

	while ((opt = getopt_long(argc, argv, "vhSFi:", long_options,
				  &longindex)) != -1) {
		switch (opt) {
		case 'S':
			generic = true;
			break;
		case 'F':
			force = true;
			break;
		case 'i':
			interval = strtoul(optarg, NULL, 0);
			break;
		case 'v':
			sample_switch_mode();
			break;
		default:
			usage(argv, long_options, __doc__, mask, true);
			goto end_destroy;
		}

		num_ifindex--;
		ifname_list++;
	}

	if (optind == argc) {
		usage(argv, long_options, __doc__, mask, true);
		goto end_destroy;
	}

	ret = sample_init_pre_load(skel);
	if (ret < 0) {
		fprintf(stderr, "Failed to sample_init_pre_load: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	ret = xdp_router_ipv4__load(skel);
	if (ret < 0) {
		fprintf(stderr, "Failed to xdp_router_ipv4__load: %s\n",
			strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	ret = sample_init(skel, mask);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize sample: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_destroy;
	}

	for (i = 0; i < num_ifindex; i++) {
		int index = if_nametoindex(ifname_list[i]);

		if (!index) {
			fprintf(stderr, "Failed to translate interface name %s\n",
				ifname_list[i]);
			goto end_destroy;
		}
		if (sample_install_xdp(skel->progs.xdp_router_ipv4_prog, index,
				       generic, force) < 0) {
			fprintf(stderr, "Failed to install xdp prog on %s\n",
				ifname_list[i]);
			goto end_destroy;
		}
	}

	get_route_table(skel, AF_INET);
	get_arp_table(skel, AF_INET);

	ret = sample_run(interval, monitor_route, skel);
	if (ret < 0) {
		fprintf(stderr, "Failed during sample run: %s\n",
			strerror(-ret));
		ret = EXIT_FAIL;
		goto end_destroy;
	}
	ret = EXIT_OK;

end_destroy:
	xdp_router_ipv4__destroy(skel);
end:
	sample_exit(ret);
}
