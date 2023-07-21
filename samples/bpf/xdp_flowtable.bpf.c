/* Copyright (c) 2017 Covalent IO, Inc. http://covalent.io
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

#include "vmlinux.h"
#include "xdp_sample.bpf.h"
#include "xdp_sample_shared.h"

#define MAX_ERRNO	4095
#define IS_ERR_VALUE(x) (unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO

#define ETH_P_IP	0x0800
#define IPV6_FLOWINFO_MASK	__cpu_to_be32(0x0fffffff)

struct flow_offload_tuple_rhash *
bpf_xdp_flow_offload_lookup(struct xdp_md *,
			    struct bpf_fib_lookup *, u32) __ksym;
int bpf_xdp_flow_offload_inet(struct xdp_md *,
			      struct flow_offload_tuple_rhash *) __ksym;
int bpf_xdp_flow_offload_xmit(struct xdp_md *,
			      struct flow_offload_tuple_rhash *) __ksym;

SEC("xdp")
int xdp_flowtable(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct flow_offload_tuple_rhash *tuplehash;
	struct bpf_fib_lookup fib_params = {
		.ifindex = ctx->ingress_ifindex,
	};
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct flow_ports *ports;
	int ret, ifindex;

	if (eth + 1 > data_end)
		return XDP_DROP;

	switch (eth->h_proto) {
	case bpf_htons(ETH_P_IP): {
		struct iphdr *iph = data + sizeof(*eth);

		ports = (struct flow_ports *)(iph + 1);
		if (ports + 1 > data_end)
			return XDP_DROP;

		fib_params.family	= AF_INET;
		fib_params.tos		= iph->tos;
		fib_params.l4_protocol	= iph->protocol;
		fib_params.tot_len	= bpf_ntohs(iph->tot_len);
		fib_params.ipv4_src	= iph->saddr;
		fib_params.ipv4_dst	= iph->daddr;
		fib_params.sport	= ports->source;
		fib_params.dport	= ports->dest;
		break;
	}
	case bpf_htons(ETH_P_IPV6): {
		struct in6_addr *src = (struct in6_addr *)fib_params.ipv6_src;
		struct in6_addr *dst = (struct in6_addr *)fib_params.ipv6_dst;
		struct ipv6hdr *ip6h = data + sizeof(*eth);

		ports = (struct flow_ports *)(ip6h + 1);
		if (ports + 1 > data_end)
			return XDP_DROP;

		fib_params.family	= AF_INET6;
		fib_params.l4_protocol	= ip6h->nexthdr;
		fib_params.tot_len	= bpf_ntohs(ip6h->payload_len);
		*src			= ip6h->saddr;
		*dst			= ip6h->daddr;
		fib_params.sport	= ports->source;
		fib_params.dport	= ports->dest;
		break;
	}
	default:
		return XDP_PASS;
	}

	tuplehash = bpf_xdp_flow_offload_lookup(ctx, &fib_params,
						 sizeof(fib_params));
	if (IS_ERR_VALUE(tuplehash))
		return XDP_PASS;

	if (bpf_xdp_flow_offload_inet(ctx, tuplehash) < 0)
		return XDP_PASS;

	ifindex = bpf_xdp_flow_offload_xmit(ctx, tuplehash);
	if (ifindex < 0)
		return XDP_PASS;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph = data + sizeof(*eth);

		bpf_printk("%pI4 (%d) -> %pI4 (%d) 0x%02x IFINDEX %d",
			   &iph->saddr, bpf_ntohs(tuplehash->tuple.src_port),
			   &iph->daddr, bpf_ntohs(tuplehash->tuple.dst_port),
			   iph->protocol, ifindex);
	}

	return bpf_redirect(ifindex, 0);
}

char _license[] SEC("license") = "GPL";
