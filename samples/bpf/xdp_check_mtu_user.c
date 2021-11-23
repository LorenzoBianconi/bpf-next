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
#include <getopt.h>
#include <libgen.h>

#include "bpf_util.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bpf_util.h"
#include "xdp_sample_user.h"
#include "xdp_check_mtu.skel.h"

struct ip_mtu_pair {
	__be32 dst;
	__u32 mtu;
};
static struct ip_mtu_pair *ip_mtu_list;
static int if_index;
static int mask;

DEFINE_SAMPLE_INIT(xdp_check_mtu);

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
	int i, opt, ret = EXIT_FAIL_OPTION;
	struct bpf_map *mtu_ipv4_map;
	struct xdp_check_mtu *skel;
	struct bpf_program *prog;
	bool generic = false;

	while ((opt = getopt(argc, argv, "hS")) != -1) {
		switch (opt) {
		case 'S':
			generic = true;
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
		goto out;
	}

	if_index = if_nametoindex(argv[optind]);
	if (!if_index) {
		fprintf(stderr, "Failed to translate interface name %s\n",
			argv[optind]);
		goto out;
	}

	if (parse_ip_mtu_pair(argv[optind + 1], argc - 1 - optind)) {
		usage(basename(argv[0]));
		goto out;
	}

	skel = xdp_check_mtu__open();
	if (!skel) {
		fprintf(stderr, "Failed to xdp_check_mtu__open: %s\n",
			strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto out;
	}

	ret = sample_init(skel, mask);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize sample: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto out_destroy;
	}

	prog = skel->progs.xdp_check_mtu;
	if (sample_install_xdp(prog, if_index, generic, false) < 0) {
		fprintf(stderr, "Failed to install XDP program\n");
		ret = EXIT_FAIL_XDP;
		goto out_destroy;
	}

	mtu_ipv4_map = skel->maps.mtu_ipv4_match;
	for (i = 0; i < argc - 1 - optind; i++) {
		ret = bpf_map_update_elem(bpf_map__fd(mtu_ipv4_map),
					  &ip_mtu_list[i].dst,
					  &ip_mtu_list[i].mtu, 0);
		if (ret < 0) {
			fprintf(stderr, "Failed to update map value %s\n",
				strerror(errno));
			ret = EXIT_FAIL_BPF;
			goto out_destroy;
		}
	}

	ret = sample_run(1, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "Failed during sample run: %s\n",
			strerror(-ret));
		ret = EXIT_FAIL;
		goto out_destroy;
	}
	ret = EXIT_OK;

out_destroy:
	xdp_check_mtu__destroy(skel);
out:
	free(ip_mtu_list);
	sample_exit(ret);
}
