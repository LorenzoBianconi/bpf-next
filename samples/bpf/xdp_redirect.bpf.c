// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2016 John Fastabend <john.r.fastabend@intel.com>
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
#include "vmlinux.h"
#include "xdp_sample.bpf.h"
#include "xdp_sample_shared.h"

const volatile int ifindex_out;

SEC("xdp.frags")
int xdp_redirect_prog(struct xdp_md *ctx)
{
	u8 src[] = { 0x00, 0x02, 0x22, 0x33, 0x44, 0x55 };
	u8 dst[] = { 0x00, 0x22, 0x22, 0x33, 0x44, 0x55 };
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	u32 key = bpf_get_smp_processor_id();
	struct ethhdr *eth = data;
	struct datarec *rec;
	u64 nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		return XDP_PASS;
	NO_TEAR_INC(rec->processed);

	if (eth->h_proto != bpf_htons(0x0800))
		return XDP_PASS;

	//swap_src_dst_mac(data);
	__builtin_memcpy(eth->h_dest, dst, 6);
	__builtin_memcpy(eth->h_source, src, 6);
	bpf_printk("%s-%d: ifindex_out %d\n", __func__, __LINE__, ifindex_out);
	return bpf_redirect(ifindex_out, 0);
}

/* Redirect require an XDP bpf_prog loaded on the TX device */
SEC("xdp.frags")
int xdp_redirect_dummy_prog(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
