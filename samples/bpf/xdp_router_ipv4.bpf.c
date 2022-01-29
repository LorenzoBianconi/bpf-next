/* Copyright (C) 2017 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#include "vmlinux.h"
#include "xdp_sample.bpf.h"
#include "xdp_sample_shared.h"

struct trie_value {
	__u8 prefix[4];
	__be64 value;
	int ifindex;
	int metric;
	__be32 gw;
};

/* Key for lpm_trie */
union key_4 {
	u32 b32[2];
	u8 b8[8];
};

struct arp_entry {
	__be64 mac;
	__be32 dst;
};

struct direct_map {
	struct arp_entry arp;
	int ifindex;
	__be64 mac;
};

/* Map for trie implementation */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(key_size, 8);
	__uint(value_size, sizeof(struct trie_value));
	__uint(max_entries, 50);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} lpm_map SEC(".maps");

/* Map for ARP table */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be32);
	__type(value, __be64);
	__uint(max_entries, 50);
} arp_table SEC(".maps");

/* Map to keep the exact match entries in the route table */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be32);
	__type(value, struct direct_map);
	__uint(max_entries, 50);
} exact_match SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 100);
} tx_port SEC(".maps");

SEC("xdp")
int xdp_router_ipv4_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	__be64 *dest_mac = NULL, *src_mac = NULL;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	u32 nh_off = sizeof(*eth);
	struct datarec *rec;
	int dst_ifindex;
	__be16 h_proto;
	u32 key = 0;

	if (data + nh_off > data_end)
		return XDP_DROP;

	h_proto = eth->h_proto;

	if (h_proto == bpf_htons(ETH_P_8021Q) ||
	    h_proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return XDP_DROP;

		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (rec)
		NO_TEAR_INC(rec->processed);

	if (h_proto == bpf_htons(ETH_P_ARP)) {
		return XDP_PASS;
	} else if (h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = data + nh_off;
		struct direct_map *direct_entry;

		if (iph + 1 > data_end)
			return XDP_DROP;

		/* Check for exact match, this would give a faster lookup*/
		direct_entry = bpf_map_lookup_elem(&exact_match, &iph->daddr);

		if (direct_entry && direct_entry->mac && direct_entry->arp.mac) {
			src_mac = &direct_entry->mac;
			dest_mac = &direct_entry->arp.mac;
			dst_ifindex = direct_entry->ifindex;
		} else {
			struct trie_value *prefix_value;
			union key_4 key4;

			/* Look up in the trie for lpm */
			key4.b32[0] = 32;
			key4.b8[4] = iph->daddr & 0xff;
			key4.b8[5] = (iph->daddr >> 8) & 0xff;
			key4.b8[6] = (iph->daddr >> 16) & 0xff;
			key4.b8[7] = (iph->daddr >> 24) & 0xff;

			prefix_value = bpf_map_lookup_elem(&lpm_map, &key4);
			if (!prefix_value) {
				if (rec)
					NO_TEAR_INC(rec->dropped);
				return XDP_DROP;
			}

			src_mac = &prefix_value->value;
			if (!src_mac) {
				if (rec)
					NO_TEAR_INC(rec->dropped);
				return XDP_DROP;
			}

			dest_mac = bpf_map_lookup_elem(&arp_table, &iph->daddr);
			if (!dest_mac) {
				if (!prefix_value->gw) {
					if (rec)
						NO_TEAR_INC(rec->dropped);
					return XDP_DROP;
				}
				dest_mac = bpf_map_lookup_elem(&arp_table,
							       &prefix_value->gw);
			}
			dst_ifindex = prefix_value->ifindex;
		}
	}

	if (!src_mac || !dest_mac) {
		if (rec)
			NO_TEAR_INC(rec->dropped);
		return XDP_DROP;
	}
	
	__builtin_memcpy(eth->h_dest, dest_mac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);

	return bpf_redirect_map(&tx_port, dst_ifindex, 0);
}

char _license[] SEC("license") = "GPL";
