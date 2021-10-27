// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020 NTT Corp. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <signal.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define STRERR_BUFSIZE  128

static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static int keep_run = 1;
static int if_list[32];
static int n_if = 0;

static int do_attach(int idx, int prog_fd, int map_fd, const char *name)
{
	int err;

	err = bpf_set_link_xdp_fd(idx, prog_fd, xdp_flags);
	if (err < 0) {
		printf("ERROR: failed to attach program to %s\n", name);
		return err;
	}

	/* Adding ifindex as a possible egress TX port */
	err = bpf_map_update_elem(map_fd, &idx, &idx, 0);
	if (err)
		printf("ERROR: failed using device %s as TX-port\n", name);

	return err;
}

static void signal_handler(int sig)
{
	int i;

	keep_run = 0;
	for (i = 0; i < n_if; i++) {
		int err;

		err = bpf_set_link_xdp_fd(if_list[i], -1, xdp_flags);
		if (err < 0)
			printf("ERROR: failed to detach program from interface %d\n", if_list[i]);
	}
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [OPTS] interface-list\n"
		"\nOPTS:\n"
		"    -Q    enable vlan filtering (802.1Q)\n"
		"    -A    enable vlan filtering (802.1ad)\n"
		"    -d    detach program\n",
		prog);
}

int main(int argc, char **argv)
{
	struct bpf_object_open_attr attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
	};
	const char *prog_name = "xdp_bridge_prog";
	int prog_fd = -1, map_fd = -1;
	struct bpf_program *prog;
	char filename[PATH_MAX];
	struct bpf_object *obj;
	int opt, i, idx, err;
	struct bpf_map *map;
	int ret = 0;

	while ((opt = getopt(argc, argv, ":QASF")) != -1) {
		switch (opt) {
		case 'S':
			xdp_flags |= XDP_FLAGS_SKB_MODE;
			break;
		case 'F':
			xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		case 'Q':
			prog_name = "xdp_8021q_bridge_prog";
			break;
		case 'A':
			prog_name = "xdp_8021q_bridge_prog";
			break;
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}

	if (!(xdp_flags & XDP_FLAGS_SKB_MODE))
		xdp_flags |= XDP_FLAGS_DRV_MODE;

	if (optind == argc) {
		usage(basename(argv[0]));
		return 1;
	}

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	attr.file = filename;

	if (access(filename, O_RDONLY) < 0) {
		printf("error accessing file %s: %s\n",
			filename, strerror(errno));
		return 1;
	}

	obj = bpf_object__open_xattr(&attr);
	if (libbpf_get_error(obj)) {
		printf("cannot open xdp program: %s\n", strerror(errno));
		return 1;
	}

	map = bpf_object__find_map_by_name(obj, "br_ports");
	if (libbpf_get_error(map)) {
		printf("map not found: %s\n", strerror(errno));
		goto err;
	}

	err = bpf_object__load(obj);
	if (err) {
		printf("cannot load xdp program: %s\n", strerror(errno));
		goto err;
	}

	prog = bpf_object__find_program_by_name(obj, prog_name);
	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 0) {
		printf("program not found: %s\n", strerror(prog_fd));
		goto err;
	}

	map_fd = bpf_map__fd(map);
	if (map_fd < 0) {
		printf("map not found: %s\n", strerror(map_fd));
		goto err;
	}

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	for (i = optind; i < argc; i++) {
		idx = if_nametoindex(argv[i]);
		if (!idx)
			idx = strtoul(argv[i], NULL, 0);

		if (!idx) {
			fprintf(stderr, "Invalid arg\n");
			return 1;
		}
		if_list[n_if++] = idx;

		err = do_attach(idx, prog_fd, map_fd, argv[i]);
		if (err)
			ret = err;
	}

	while (keep_run)
		sleep(1);

	return ret;
err:
    bpf_object__close(obj);
    return 1;
}
