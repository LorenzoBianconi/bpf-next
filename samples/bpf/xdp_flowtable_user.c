// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2017 Covalent IO, Inc. http://covalent.io
 */
static const char *__doc__ =
"XDP flowtable integration example\n"
"Usage: xdp_flowtable <IFINDEX|IFNAME>\n";

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <libgen.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bpf_util.h"
#include "xdp_sample_user.h"
#include "xdp_flowtable.skel.h"

static int mask = SAMPLE_RX_CNT | SAMPLE_EXCEPTION_CNT;

DEFINE_SAMPLE_INIT(xdp_flowtable);

static const struct option long_options[] = {
	{ "help", no_argument, NULL, 'h' },
	{}
};

int main(int argc, char **argv)
{
	struct xdp_flowtable *skel;
	int ret = EXIT_FAIL_OPTION;
	char ifname[IF_NAMESIZE];
	int ifindex;
	int opt;

	while ((opt = getopt_long(argc, argv, "h",
				  long_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
		default:
			sample_usage(argv, long_options, __doc__, mask, false);
			return ret;
		}
	}

	if (argc <= optind) {
		sample_usage(argv, long_options, __doc__, mask, true);
		goto end;
	}

	ifindex = if_nametoindex(argv[optind]);
	if (!ifindex)
		ifindex = strtoul(argv[optind], NULL, 0);

	if (!ifindex) {
		fprintf(stderr, "Bad interface index or name\n");
		sample_usage(argv, long_options, __doc__, mask, true);
		goto end;
	}

	skel = xdp_flowtable__open();
	if (!skel) {
		fprintf(stderr, "Failed to xdp_flowtable__open: %s\n",
			strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end;
	}

	ret = sample_init_pre_load(skel);
	if (ret < 0) {
		fprintf(stderr, "Failed to sample_init_pre_load: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	ret = xdp_flowtable__load(skel);
	if (ret < 0) {
		fprintf(stderr, "Failed to xdp_flowtable__load: %s\n",
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

	if (sample_install_xdp(skel->progs.xdp_flowtable,
			       ifindex, false, false) < 0) {
		ret = EXIT_FAIL_XDP;
		goto end_destroy;
	}

	ret = EXIT_FAIL;
	if (!if_indextoname(ifindex, ifname)) {
		fprintf(stderr, "Failed to if_indextoname for %d: %s\n", ifindex,
			strerror(errno));
		goto end_destroy;
	}

	ret = sample_run(2, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "Failed during sample run: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_destroy;
	}
	ret = EXIT_OK;
end_destroy:
	xdp_flowtable__destroy(skel);
end:
	sample_exit(ret);
}
