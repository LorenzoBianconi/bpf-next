// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2017 Cavium, Inc.
 */
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <bpf/libbpf.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <net/if.h>

#include "bpf_util.h"
#include <bpf/bpf.h>
#include <libgen.h>

struct ip_mtu_pair {
	__be32 dst;
	__u32 mtu;
};
static struct ip_mtu_pair *ip_mtu_list;

static int flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static int mtu_ipv4_match_fd;
static int if_index;

static void close_and_exit(int sig)
{
	__u32 prog_id = 0;

	if (bpf_get_link_xdp_id(if_index, &prog_id, flags)) {
		printf("bpf_get_link_xdp_id on iface %d failed\n", if_index);
		exit(1);
	}
	if (prog_id)
		bpf_set_link_xdp_fd(if_index, -1, flags);
	exit(0);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"%s: %s [-S] <interface> <IP0:mtu0> <IP1:mtu1>..\n\n"
		"OPTS:\n"
		"    -S    use skb-mode\n",
		__func__, prog);
}

static int parse_ip_mtu_pair(char *pair, int n_pair)
{
	char *t0, *r0 = NULL;
	int i = 0;

	ip_mtu_list = (struct ip_mtu_pair *)calloc(n_pair,
						   sizeof(*ip_mtu_list));
	if (!ip_mtu_list)
		return 1;

	for (t0 = strtok_r(pair, " ", &r0); t0;
	     t0 = strtok_r(NULL, " ", &r0)) {
		char *t1, *r1 = NULL;
		int j = 0;

		for (t1 = strtok_r(t0, ":", &r1); t1;
		     t1 = strtok_r(NULL, ":", &r1)) {
			if (!j) {
				__u32 addr;

				if (!inet_pton(AF_INET, t1, &addr))
					return 1;

				ip_mtu_list[i].dst = addr;
				j++;
			} else {
				long int mtu = strtol(t1, NULL, 10);

				if (!mtu)
					return 1;

				ip_mtu_list[i++].mtu = mtu;
				break;
			}
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
	};
	const char *optstr = "hS";
	struct bpf_object *obj;
	int prog_fd, i, opt;
	char filename[256];

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	prog_load_attr.file = filename;

	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
		case 'S':
			flags |= XDP_FLAGS_SKB_MODE;
			break;
		case 'h':
			usage(basename(argv[0]));
			return 0;
		default:
			break;
		}
	}
	if (argc < optind + 2) {
		usage(basename(argv[0]));
		return 1;
	}

	if_index = if_nametoindex(argv[optind]);
	if (!if_index) {
		printf("Couldn't translate interface name: %s", argv[optind]);
		return 1;
	}

	if (parse_ip_mtu_pair(argv[optind + 1], argc - 1 - optind)) {
		usage(basename(argv[0]));
		goto error;
	}

	if (!(flags & XDP_FLAGS_SKB_MODE))
		flags |= XDP_FLAGS_DRV_MODE;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		goto error;

	if (!prog_fd) {
		printf("bpf_prog_load_xattr: %s\n", strerror(errno));
		goto error;
	}

	if (bpf_set_link_xdp_fd(if_index, prog_fd, flags) < 0) {
		printf("link set xdp fd failed\n");
		goto error;
	}

	mtu_ipv4_match_fd = bpf_object__find_map_fd_by_name(obj,
							    "mtu_ipv4_match");
	if (mtu_ipv4_match_fd < 0) {
		printf("bpf_object__find_map_fd_by_name failed\n");
		goto error;
	}

	for (i = 0; i < argc - 1 - optind; i++) {
		if (bpf_map_update_elem(mtu_ipv4_match_fd, &ip_mtu_list[i].dst,
					&ip_mtu_list[i].mtu, 0) < 0)
			goto error;
	}
	free(ip_mtu_list);

	signal(SIGINT, close_and_exit);
	signal(SIGTERM, close_and_exit);

	while (true)
		sleep(1);

	return 0;

error:
	free(ip_mtu_list);
	return 1;
}
