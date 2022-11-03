// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2017-2018 Jesper Dangaard Brouer, Red Hat Inc.
 *
 * XDP monitor tool, based on tracepoints
 */
#include "vmlinux.h"
#include "xdp_sample.bpf.h"
f_conn;
struct bpf_ct_opts___local {
	s32 netns_id;
	s32 error;
	u8 l4proto;
	u8 dir;
	u8 reserved[2];
} __attribute__((preserve_access_index));

struct nf_conn *
bpf_xdp_ct_lookup(struct xdp_md *, struct bpf_sock_tuple *, u32,
		  struct bpf_ct_opts *, u32) __ksym;
void bpf_ct_release(struct nf_conn *) __ksym;

SEC("xdp")
int xdp_dummy_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	u64 nh_off = sizeof(*eth);
	struct datarec *rec;
	u32 key = 0;

	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (rec)
		NO_TEAR_INC(rec->processed);

	if (data + nh_off > data_end)
		goto out;

	switch (bpf_ntohs(eth->h_proto)) {
	case ETH_P_IP: {
		struct bpf_sock_tuple bpf_tuple = {};
		const char fmt_debug[] = "CT %d\n";
		struct iphdr *iph = data + nh_off;
		struct bpf_ct_opts opts_def = {
			.netns_id = -1,
		};
		struct nf_conn *ct;
		bool ret;

		if (iph + 1 > data_end)
			goto out;

		opts_def.l4proto = iph->protocol;
		bpf_tuple.ipv4.saddr = iph->saddr;
		bpf_tuple.ipv4.daddr = iph->daddr;

		if (iph->protocol == IPPROTO_TCP) {
			struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

			if (tcph + 1 > data_end)
				goto out;

			bpf_tuple.ipv4.sport = tcph->source;
			bpf_tuple.ipv4.dport = tcph->dest;
		} else if (iph->protocol == IPPROTO_UDP) {
			struct udphdr *udph = (struct udphdr *)(iph + 1);

			if (udph + 1 > data_end)
				goto out;

			bpf_tuple.ipv4.sport = udph->source;
			bpf_tuple.ipv4.dport = udph->dest;
		} else {
			goto out;
		}

		ct = bpf_xdp_ct_lookup(ctx, &bpf_tuple,
				       sizeof(bpf_tuple.ipv4),
				       &opts_def, sizeof(opts_def));
		ret = !!ct;
		if (ct)
			bpf_ct_release(ct);

		bpf_trace_printk(fmt_debug, sizeof(fmt_debug), ret);
	}
	default:
		break;
	}
out:
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
