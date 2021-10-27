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

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define STRERR_BUFSIZE  128

static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

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

static int do_detach(int idx, const char *name)
{
	int err;

	err = bpf_set_link_xdp_fd(idx, -1, xdp_flags);
	if (err < 0)
		printf("ERROR: failed to detach program from %s\n", name);

	/* FIXME: Need to delete the corresponding entry in shared devmap
	 * with bpf_map_delete_elem((map_fd, &idx);
	 */
	return err;
}

static int do_reuse_map(struct bpf_map *map, char *pin_path, bool *pinned)
{
	const char *path = "/sys/fs/bpf/xdp_bridge";
	char errmsg[STRERR_BUFSIZE];
	int err, len, pin_fd;

	len = snprintf(pin_path, PATH_MAX, "%s/%s", path, bpf_map__name(map));
	if (len < 0)
		return -EINVAL;
	else if (len >= PATH_MAX)
		return -ENAMETOOLONG;

	pin_fd = bpf_obj_get(pin_path);
	if (pin_fd < 0) {
		err = -errno;
		if (err == -ENOENT) {
			*pinned = false;
			return 0;
		}

		libbpf_strerror(-err, errmsg, sizeof(errmsg));
		printf("couldn't retrieve pinned map: %s\n", errmsg);
		return err;
	}

	err = bpf_map__reuse_fd(map, pin_fd);
	if (err) {
		printf("failed to reuse map: %s\n", strerror(errno));
		close(pin_fd);
	}

	return err;
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
	char filename[PATH_MAX], pin_path[PATH_MAX];
	const char *prog_name = "xdp_bridge";
	int prog_fd = -1, map_fd = -1;
	struct bpf_program *prog;
	struct bpf_object *obj;
	int opt, i, idx, err;
	struct bpf_map *map;
	bool pinned = true;
	int attach = 1;
	int ret = 0;

	while ((opt = getopt(argc, argv, ":dQASF")) != -1) {
		switch (opt) {
		case 'd':
			attach = 0;
			break;
		case 'S':
			xdp_flags |= XDP_FLAGS_SKB_MODE;
			break;
		case 'F':
			xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
			break;
		case 'Q':
			prog_name = "xdp_8021q_bridge";
			break;
		case 'A':
			prog_name = "xdp_8021ad_bridge";
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

	if (attach) {
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

		map = bpf_object__find_map_by_name(obj, "xdp_tx_ports");
		if (libbpf_get_error(map)) {
			printf("map not found: %s\n", strerror(errno));
			goto err;
		}

		err = do_reuse_map(map, pin_path, &pinned);
		if (err) {
			printf("error reusing map %s: %s\n",
				bpf_map__name(map), strerror(errno));
			goto err;
		}

		err = bpf_object__load(obj);
		if (err) {
			printf("cannot load xdp program: %s\n", strerror(errno));
			goto err;
		}

		prog = bpf_object__find_program_by_title(obj, prog_name);
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

		if (!pinned) {
			err = bpf_map__pin(map, pin_path);
			if (err) {
				printf("failed to pin map: %s\n", strerror(errno));
				goto err;
			}
		}
	}

	for (i = optind; i < argc; ++i) {
		idx = if_nametoindex(argv[i]);
		if (!idx)
			idx = strtoul(argv[i], NULL, 0);

		if (!idx) {
			fprintf(stderr, "Invalid arg\n");
			return 1;
		}
		if (attach) {
			err = do_attach(idx, prog_fd, map_fd, argv[i]);
			if (err)
				ret = err;
		} else {
			err = do_detach(idx, argv[i]);
			if (err)
				ret = err;
		}
	}

	return ret;
err:
    bpf_object__close(obj);
    return 1;
}
