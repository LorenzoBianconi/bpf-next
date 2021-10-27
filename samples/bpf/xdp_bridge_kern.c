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
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>


#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 64);
} br_ports SEC(".maps");

struct bpf_fdb_lookup {
	__u8	addr[6]; /* ETH_ALEN */
	__u16	vid;
	__u32	ifindex;
};

int br_fdb_find_port_from_ifindex(struct xdp_md *xdp_ctx,
				  struct bpf_fdb_lookup *opt,
				  u32 opt__sz) __ksym;

static __always_inline int xdp_bridge_proto(struct xdp_md *ctx, __be16 br_vlan_proto)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fdb_lookup params = {};
	struct vlan_hdr *vlan_hdr = NULL;
	struct ethhdr *eth = data;
	u64 nh_off = sizeof(*eth);
	int ret;

	if (data + nh_off > data_end)
		return XDP_DROP;

	if (unlikely(ntohs(eth->h_proto) < ETH_P_802_3_MIN))
		return XDP_PASS;

	/* Handle VLAN tagged packet */
	if (eth->h_proto == br_vlan_proto) {
		vlan_hdr = (void *)eth + nh_off;
		nh_off += sizeof(*vlan_hdr);
		if ((void *)eth + nh_off > data_end)
			return XDP_PASS;

		params.vid = ntohs(vlan_hdr->h_vlan_TCI) & VLAN_VID_MASK;
	}

	memcpy(params.addr, eth->h_dest, 6);

	/* Note: This program definitely takes ifindex of ingress interface as
	 * a bridge port. Linux networking devices can be stacked and physical
	 * interfaces are not necessarily slaves of bridges (e.g., bonding or
	 * vlan devices can be slaves of bridges), but stacked bridge ports are
	 * currently unsupported in this program. In such cases, XDP programs
	 * should be attached to a lower device in order to process packets with
	 * higher speed. Then, a new bpf helper to find upper devices will be
	 * required here in the future because they will be registered on FDB
	 * in the kernel.
	 */
	params.ifindex = ctx->ingress_ifindex;

	ret = br_fdb_find_port_from_ifindex(ctx, &params,
					    sizeof(struct bpf_fdb_lookup));
	if (ret < 0)
		/* In cases of flooding, XDP_PASS will be returned here */
		return XDP_PASS;

	return bpf_redirect_map(&br_ports, ret, 0);
}

SEC("xdp")
int xdp_bridge_prog(struct xdp_md *ctx)
{
	return xdp_bridge_proto(ctx, 0);
}

SEC("xdp")
int xdp_8021q_bridge_prog(struct xdp_md *ctx)
{
	return xdp_bridge_proto(ctx, htons(ETH_P_8021Q));
}

SEC("xdp")
int xdp_8021ad_bridge_prog(struct xdp_md *ctx)
{
	return xdp_bridge_proto(ctx, htons(ETH_P_8021AD));
}

char _license[] SEC("license") = "GPL";
