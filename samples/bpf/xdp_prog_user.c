// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <locale.h>
#include <getopt.h>
#include <net/if.h>
#include <time.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "bpf_util.h"
#include "xdp_sample_user.h"
#include "xdp_prog.skel.h"

static int mask = SAMPLE_RX_CNT;

DEFINE_SAMPLE_INIT(xdp_prog);

int main(int argc, char **argv)
{
	int ifindex, ret = EXIT_FAIL_OPTION;
	unsigned long interval = 2;
	struct xdp_prog *skel;

	ifindex = if_nametoindex(argv[1]);
	if (!ifindex) {
		fprintf(stderr, "Bad interface name\n");
		goto end;
	}

	skel = xdp_prog__open();
	if (!skel) {
		fprintf(stderr, "Failed to xdp_prog__open: %s\n",
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

	ret = xdp_prog__load(skel);
	if (ret < 0) {
		fprintf(stderr, "Failed to xdp_prog__load: %s\n", strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	ret = sample_init(skel, mask);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize sample: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	ret = EXIT_FAIL_XDP;
	if (sample_install_xdp(skel->progs.xdp_dummy_prog, ifindex,
			       false, false) < 0)
		goto end_destroy;

	ret = sample_run(interval, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "Failed during sample run: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_destroy;
	}

	ret = EXIT_OK;
end_destroy:
	xdp_prog__destroy(skel);
end:
	sample_exit(ret);
}
