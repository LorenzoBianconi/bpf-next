// SPDX-License-Identifier: GPL-2.0
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
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

#define ICMP_TOOBIG_SIZE		98
#define ICMP_TOOBIG_PAYLOAD_SIZE	92

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be32);
	__type(value, u32);
	__uint(max_entries, 256);
} mtu_ipv4_match SEC(".maps");

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	return ~((csum & 0xffff) + (csum >> 16));
}

static __always_inline void
ipv4_csum(void *data_start, int data_size, __u32 *csum)
{
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum = csum_fold_helper(*csum);
}

static __always_inline void
swap_mac(void *data, struct ethhdr *orig_eth)
{
	struct ethhdr *eth = data;

	memcpy(eth->h_source, orig_eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, orig_eth->h_source, ETH_ALEN);
	eth->h_proto = orig_eth->h_proto;
}

static __always_inline int
send_icmp4_too_big(struct xdp_md *xdp, int max_packet_size)
{
	int headroom = (int)sizeof(struct iphdr) + (int)sizeof(struct icmphdr);
	struct iphdr *iph, *orig_iph;
	struct icmphdr *icmp_hdr;
	struct ethhdr *orig_eth;
	void *data, *data_end;
	__u32 csum = 0;
	__u64 off = 0;

	if (bpf_xdp_adjust_head(xdp, 0 - headroom))
		return XDP_DROP;

	data_end = (void *)(long)xdp->data_end;
	data = (void *)(long)xdp->data;

	if (data + (ICMP_TOOBIG_SIZE + headroom) > data_end)
		return XDP_DROP;

	orig_eth = data + headroom;
	swap_mac(data, orig_eth);
	off += sizeof(struct ethhdr);
	iph = data + off;
	off += sizeof(struct iphdr);
	icmp_hdr = data + off;
	off += sizeof(struct icmphdr);
	orig_iph = data + off;
	icmp_hdr->type = ICMP_DEST_UNREACH;
	icmp_hdr->code = ICMP_FRAG_NEEDED;
	icmp_hdr->un.frag.mtu = htons(max_packet_size - sizeof(struct ethhdr));
	icmp_hdr->checksum = 0;
	ipv4_csum(icmp_hdr, ICMP_TOOBIG_PAYLOAD_SIZE, &csum);
	icmp_hdr->checksum = csum;
	iph->ttl = 64;
	iph->daddr = orig_iph->saddr;
	iph->saddr = orig_iph->daddr;
	iph->version = 4;
	iph->ihl = 5;
	iph->protocol = IPPROTO_ICMP;
	iph->tos = 0;
	iph->tot_len = htons(ICMP_TOOBIG_SIZE + headroom - sizeof(struct ethhdr));
	iph->check = 0;
	csum = 0;
	ipv4_csum(iph, sizeof(struct iphdr), &csum);
	iph->check = csum;

	return XDP_TX;
}

SEC("xdp_check_mtu")
int xdp_check_mtu_prog(struct xdp_md *xdp)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	int len = data_end - data;
	struct ethhdr *eth = data;
	u32 *mtu, pkt_size;
	struct iphdr *iph;

	if (data + sizeof(*eth) > data_end)
		return XDP_DROP;

	if (eth->h_proto != ntohs(ETH_P_IP))
		return XDP_PASS;

	iph = (struct iphdr *)(eth + 1);
	if (iph + 1 > data_end)
		return XDP_DROP;

	mtu = bpf_map_lookup_elem(&mtu_ipv4_match, &iph->daddr);
	if (!mtu)
		return XDP_PASS;

	pkt_size = sizeof(*eth) + *mtu;
	if (len > max(pkt_size, ICMP_TOOBIG_SIZE)) {
		int offset = len - ICMP_TOOBIG_SIZE;

		if (bpf_xdp_adjust_tail(xdp, 0 - offset))
			return XDP_PASS;

		return send_icmp4_too_big(xdp, pkt_size);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
