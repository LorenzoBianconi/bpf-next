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
} xdp_tx_ports SEC(".maps");

static __always_inline int xdp_bridge_proto(struct xdp_md *ctx, u16 br_vlan_proto)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fdb_lookup fdb_lookup_params;
	struct vlan_hdr *vlan_hdr = NULL;
	struct ethhdr *eth = data;
	u16 h_proto;
	u64 nh_off;
	int ret;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	__builtin_memset(&fdb_lookup_params, 0, sizeof(struct bpf_fdb_lookup));

	h_proto = eth->h_proto;
	if (unlikely(ntohs(h_proto) < ETH_P_802_3_MIN))
		return XDP_PASS;

	/* Handle VLAN tagged packet */
	if (h_proto == br_vlan_proto) {
		vlan_hdr = (void *)eth + nh_off;
		nh_off += sizeof(*vlan_hdr);
		if ((void *)eth + nh_off > data_end)
			return XDP_PASS;

		fdb_lookup_params.vlan_id =
			ntohs(vlan_hdr->h_vlan_TCI) & VLAN_VID_MASK;
	}

	/* FIXME: Although Linux bridge provides us with vlan filtering (contains
	 * PVID) at ingress, the feature is currently unsupported in this XDP program.
	 *
	 * Two ideas to realize the vlan filtering are below:
	 *   1. usespace daemon monitors bridge vlan events and notifies XDP programs
	 *      of them through BPF maps
	 *   2. introduce another bpf helper to retrieve bridge vlan information
	 *
	 *
	 * FIXME: After the vlan filtering, learning feature is required here, but
	 * it is currently unsupported as well. If another bpf helper for learning
	 * is accepted, the processing could be implemented in the future.
	 */

	memcpy(&fdb_lookup_params.addr, eth->h_dest, ETH_ALEN);

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
	fdb_lookup_params.ifindex = ctx->ingress_ifindex;

	ret = bpf_xdp_fdb_lookup(ctx, &fdb_lookup_params,
				 sizeof(struct bpf_fdb_lookup));
	if (ret != BPF_FDB_LKUP_RET_SUCCESS) {
		/* In cases of flooding, XDP_PASS will be returned here */
		return XDP_PASS;
	}

	/* FIXME: Although Linux bridge provides us with vlan filtering (contains
	 * untagged policy) at egress as well, the feature is currently unsupported
	 * in this XDP program.
	 *
	 * Two ideas to realize the vlan filtering are below:
	 *   1. usespace daemon monitors bridge vlan events and notifies XDP programs
	 *      of them through BPF maps
	 *   2. introduce another bpf helper to retrieve bridge vlan information
	 */

	return bpf_redirect_map(&xdp_tx_ports, fdb_lookup_params.ifindex,
				XDP_PASS);
}

SEC("xdp_bridge")
int xdp_bridge_prog(struct xdp_md *ctx)
{
	return xdp_bridge_proto(ctx, 0);
}

SEC("xdp_8021q_bridge")
int xdp_8021q_bridge_prog(struct xdp_md *ctx)
{
	return xdp_bridge_proto(ctx, htons(ETH_P_8021Q));
}

SEC("xdp_8021ad_bridge")
int xdp_8021ad_bridge_prog(struct xdp_md *ctx)
{
	return xdp_bridge_proto(ctx, htons(ETH_P_8021AD));
}

char _license[] SEC("license") = "GPL";
