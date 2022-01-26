// SPDX-License-Identifier: GPL-2.0-only
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#define KBUILD_MODNAME "foo"

#include "vmlinux.h"
#include "xdp_sample.bpf.h"
#include "xdp_sample_shared.h"

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 64);
} br_ports SEC(".maps");

int br_fdb_find_port_from_ifindex(struct xdp_md *xdp_ctx,
				  const u8 *addr, u32 ifindex,
				  u16 vid) __ksym;

SEC("xdp")
int xdp_fdb_lookup(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	u32 key = bpf_get_smp_processor_id();
	struct ethhdr *eth = data;
	u64 nh_off = sizeof(*eth);
	struct datarec *rec;
	int ret;

	if (data + nh_off > data_end)
		return XDP_DROP;

	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		return XDP_PASS;

	NO_TEAR_INC(rec->processed);

	ret = br_fdb_find_port_from_ifindex(ctx, eth->h_dest,
					    ctx->ingress_ifindex, 0);
	if (ret < 0)
		/* In cases of flooding, XDP_PASS will be returned here */
		return XDP_PASS;

	return bpf_redirect_map(&br_ports, ret, 0);
}

char _license[] SEC("license") = "GPL";
