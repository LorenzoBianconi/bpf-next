/* Copyright (C) 2017 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#include "vmlinux.h"
#include "xdp_sample.bpf.h"
#include "xdp_sample_shared.h"

#define ETH_ALEN	6
#define ETH_P_8021Q	0x8100
#define ETH_P_8021AD	0x88A8

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

/* xdp ct */
struct nf_conn;
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
void bpf_ct_set_timeout(struct nf_conn___init *, u32) __ksym;
int bpf_ct_set_status(const struct nf_conn___init *, u32 ) __ksym;
int bpf_ct_change_timeout(struct nf_conn *, u32) __ksym;
int bpf_ct_set_nat_info(struct nf_conn___init *, union nf_inet_addr *,
			__be16 *, enum nf_nat_manip_type) __ksym;
struct nf_conn___init *
bpf_xdp_ct_alloc(struct xdp_md *, struct bpf_sock_tuple *,
		 u32, struct bpf_ct_opts *, u32)  __ksym;
struct nf_conn *bpf_ct_insert_entry(struct nf_conn___init *) __ksym;

static __always_inline __u16 csum_fold_helper(__wsum sum)
{
	sum = (sum & 0xffff) + (sum >> 16);
	return ~((sum & 0xffff) + (sum >> 16));
}

static __always_inline __u16 ipv4_csum(void *data_start, int data_size)
{
	__wsum sum;

	sum = bpf_csum_diff(0, 0, data_start, data_size, 0);
	return csum_fold_helper(sum);
}

static __always_inline __wsum csum_unfold(__sum16 n)
{
	return (__wsum)n;
}

static __always_inline __wsum csum_add(__wsum csum, __wsum addend)
{
	u32 res = (u32)csum;
	res += (u32)addend;
	return (__wsum)(res + (res < (u32)addend));
}

static __always_inline __wsum csum_sub(__wsum csum, __wsum addend)
{
	return csum_add(csum, ~addend);
}

static inline __sum16 csum_fold(__wsum csum)
{
	u32 sum = (u32)csum;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__sum16)~sum;
}

static __always_inline void csum_replace4(__sum16 *sum, __be32 from, __be32 to)
{
	__wsum tmp = csum_sub(~csum_unfold(*sum), (__wsum)from);

	*sum = csum_fold(csum_add(tmp, (__wsum)to));
}

static __always_inline void
xdp_router_dump_pkt_info(struct iphdr *iph, void *data_end)
{
	const char fmt_l3_str[] = "src:%pI4 dst:%pI4 proto:%02x";
	const char fmt_l4_str[] = "sport:%u dport:%u";

	if (iph + 1 > data_end)
		return;

	bpf_trace_printk(fmt_l3_str, sizeof(fmt_l3_str), &iph->saddr,
			 &iph->daddr, iph->protocol);
	if (iph->protocol == IPPROTO_TCP) {
		const char fmt_tcp_flags1[] = "SYN:%d ACK:%d PSH:%d";
		const char fmt_tcp_flags2[] = "RST:%d FIN:%d URG:%d";
		struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

		if (tcph + 1 > data_end)
			return;

		bpf_trace_printk(fmt_l4_str, sizeof(fmt_l4_str),
				 bpf_ntohs(tcph->source),
				 bpf_ntohs(tcph->dest));
		bpf_trace_printk(fmt_tcp_flags1, sizeof(fmt_tcp_flags1),
				 tcph->syn, tcph->ack, tcph->psh);
		bpf_trace_printk(fmt_tcp_flags2, sizeof(fmt_tcp_flags2),
				 tcph->rst, tcph->fin, tcph->urg);
	} else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph = (struct udphdr *)(iph + 1);

		if (udph + 1 > data_end)
			return;

		bpf_trace_printk(fmt_l4_str, sizeof(fmt_l4_str),
				 bpf_ntohs(udph->source),
				 bpf_ntohs(udph->dest));
	}
}

static __always_inline int
xdp_router_snat(struct xdp_md *ctx, struct iphdr *iph,
		struct datarec *rec)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct bpf_ct_opts opts_def = {
		.l4proto = iph->protocol,
		.netns_id = -1,
	};
	struct bpf_sock_tuple bpf_tuple = {
		.ipv4.saddr = iph->saddr,
		.ipv4.daddr = iph->daddr,
	};
	struct nf_conntrack_tuple *tuple;
	__be16 sport, dport;
	struct nf_conn *ct;
	__sum16 *check;

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

		if (tcph + 1 > data_end) {
			if (rec)
				NO_TEAR_INC(rec->xdp_drop);
			return XDP_DROP;
		}

		if (tcph->fin || tcph->rst) {
			if (rec)
				NO_TEAR_INC(rec->xdp_pass);
			return XDP_PASS;
		}

		bpf_tuple.ipv4.sport = tcph->source;
		bpf_tuple.ipv4.dport = tcph->dest;
		check = &tcph->check;
	} else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph = (struct udphdr *)(iph + 1);

		if (udph + 1 > data_end) {
			if (rec)
				NO_TEAR_INC(rec->xdp_drop);
			return XDP_DROP;
		}

		bpf_tuple.ipv4.sport = udph->source;
		bpf_tuple.ipv4.dport = udph->dest;
		check = &udph->check;
	} else {
		return XDP_PASS;
	}

	ct = bpf_xdp_ct_lookup(ctx, &bpf_tuple, sizeof(bpf_tuple.ipv4),
			       &opts_def, sizeof(opts_def));
	if (!ct) {
		struct nf_conn___init *nct = bpf_xdp_ct_alloc(ctx,
				&bpf_tuple, sizeof(bpf_tuple.ipv4),
				&opts_def, sizeof(opts_def));
		union nf_inet_addr addr = {
			.ip = 0x0102a8c0, /* 192.168.2.1 */
		};

		if (!nct) {
			if (rec)
				NO_TEAR_INC(rec->xdp_pass);
			return XDP_PASS;
		}

		bpf_ct_set_nat_info(nct, &addr, NULL, NF_NAT_MANIP_SRC);
		bpf_ct_set_timeout(nct, 30000);
		bpf_ct_set_status(nct, IP_CT_NEW);

		ct = bpf_ct_insert_entry(nct);
		if (ct)
			bpf_ct_release(ct);

		if (rec)
			NO_TEAR_INC(rec->xdp_pass);
		return XDP_PASS;
	}

	if (iph->protocol == IPPROTO_TCP &&
	    ct->proto.tcp.state != TCP_CONNTRACK_ESTABLISHED) {
		/* let the kernel manage tcp conntrack state machine */
		bpf_ct_release(ct);
		if (rec)
			NO_TEAR_INC(rec->xdp_pass);
		return XDP_PASS;
	}

	if (!bpf_core_field_exists(opts_def.dir)) {
		bpf_ct_release(ct);
		if (rec)
			NO_TEAR_INC(rec->xdp_pass);
		return XDP_PASS;
	}

	/* perform snat and recompute the csum */
	if (opts_def.dir == IP_CT_DIR_REPLY) {
		tuple = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
		csum_replace4(check, iph->daddr, tuple->src.u3.ip);
		iph->daddr = tuple->src.u3.ip;
	} else {
		tuple = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;
		csum_replace4(check, iph->saddr, tuple->dst.u3.ip);
		iph->saddr = tuple->dst.u3.ip;
	}

	iph->ttl--;
	iph->check = 0;
	iph->check = ipv4_csum(iph, sizeof(*iph));

	/* update ct lifetime */
	bpf_ct_change_timeout(ct, 30000);

	bpf_ct_release(ct);

	xdp_router_dump_pkt_info(iph, data_end);

	return XDP_REDIRECT;
}

SEC("xdp")
int xdp_router_ipv4_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	u64 nh_off = sizeof(*eth);
	struct datarec *rec;
	__be16 h_proto;
	u32 key = 0;
	int ret;

	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (rec)
		NO_TEAR_INC(rec->processed);

	if (data + nh_off > data_end)
		goto drop;

	h_proto = eth->h_proto;
	if (h_proto == bpf_htons(ETH_P_8021Q) ||
	    h_proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			goto drop;

		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	switch (bpf_ntohs(h_proto)) {
	case ETH_P_ARP:
		if (rec)
			NO_TEAR_INC(rec->xdp_pass);
		return XDP_PASS;
	case ETH_P_IP: {
		struct iphdr *iph = data + nh_off;
		struct direct_map *direct_entry;
		__be64 *dest_mac, *src_mac;
		int forward_to;

		if (iph + 1 > data_end)
			goto drop;

		/* snat for TCP and UDP */
		ret = xdp_router_snat(ctx, iph, rec);
		if (ret != XDP_REDIRECT)
			return ret;

		direct_entry = bpf_map_lookup_elem(&exact_match, &iph->daddr);

		/* Check for exact match, this would give a faster lookup */
		if (direct_entry && direct_entry->mac &&
		    direct_entry->arp.mac) {
			src_mac = &direct_entry->mac;
			dest_mac = &direct_entry->arp.mac;
			forward_to = direct_entry->ifindex;
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
			if (!prefix_value)
				goto drop;

			forward_to = prefix_value->ifindex;
			src_mac = &prefix_value->value;
			if (!src_mac)
				goto drop;

			dest_mac = bpf_map_lookup_elem(&arp_table, &iph->daddr);
			if (!dest_mac) {
				if (!prefix_value->gw)
					goto drop;

				dest_mac = bpf_map_lookup_elem(&arp_table,
							       &prefix_value->gw);
				if (!dest_mac) {
					/* Forward the packet to the kernel in
					 * order to trigger ARP discovery for
					 * the default gw.
					 */
					if (rec)
						NO_TEAR_INC(rec->xdp_pass);
					return XDP_PASS;
				}
			}
		}

		if (src_mac && dest_mac) {
			__builtin_memcpy(eth->h_dest, dest_mac, ETH_ALEN);
			__builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);

			ret = bpf_redirect_map(&tx_port, forward_to, 0);
			if (ret == XDP_REDIRECT) {
				if (rec)
					NO_TEAR_INC(rec->xdp_redirect);
				return ret;
			}
		}
	}
	default:
		break;
	}
drop:
	if (rec)
		NO_TEAR_INC(rec->xdp_drop);

	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
