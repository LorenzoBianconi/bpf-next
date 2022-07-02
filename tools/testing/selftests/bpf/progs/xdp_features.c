// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "xdping.h"
#include "../xdp_features_test.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, struct pinginfo);
} ping_map SEC(".maps");

unsigned char source[6];
int test_ifindex;
u64 count;
u64 key;

bool test_aborted_done;
bool test_drop_done;
bool test_pass_done;
bool test_tx_done;
bool test_redirect_done;
bool test_redirect_cpumap;
bool test_redirect_devmap;

bool trace_exception;
bool trace_invalid;
bool trace_redirect;
bool xdp_generic_done;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
} ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key_type, u64);
	__type(value_type, u64);
	__uint(max_entries, 1);
} ctx_map SEC(".maps");

static __always_inline bool equal_source(unsigned char a[6], unsigned char b[6])
{
	for (int i = 0; i < 6; i++) {
		if (a[i] != b[i])
			return false;
	}
	return true;
}

static __always_inline bool prep_packet(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *e;

	if (data + sizeof(*e) > data_end)
		return false;
	e = data;
	data += sizeof(*e);
	if (data + sizeof(key) > data_end)
		return false;
	__builtin_memcpy(e->h_source, source, sizeof(e->h_source));
	return true;
}

static __always_inline void swap_src_dst_mac(void *data)
{
	unsigned short *p = data;
	unsigned short dst[3];

	dst[0] = p[0];
	dst[1] = p[1];
	dst[2] = p[2];
	p[0] = p[3];
	p[1] = p[4];
	p[2] = p[5];
	p[3] = dst[0];
	p[4] = dst[1];
	p[5] = dst[2];
}

#define ICMP_ECHOREPLY 0
#define ICMP_ECHO_LEN  64
#define ETH_P_IP       0x0800
#define ICMP_ECHO      8

static __always_inline int icmp_check(struct xdp_md *ctx, int type)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct icmphdr *icmph;
	struct iphdr *iph;

	if (data + sizeof(*eth) + sizeof(*iph) + ICMP_ECHO_LEN > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	iph = data + sizeof(*eth);

	if (iph->protocol != IPPROTO_ICMP)
		return XDP_PASS;

	if (bpf_ntohs(iph->tot_len) - sizeof(*iph) != ICMP_ECHO_LEN)
		return XDP_PASS;

	icmph = data + sizeof(*eth) + sizeof(*iph);

	if (icmph->type != type)
		return XDP_PASS;

	return XDP_TX;
}

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

SEC("xdp")
int test_xdp_features(struct xdp_md *ctx)
{
	if (!test_aborted_done)
		return XDP_ABORTED;
	if (!test_drop_done)
		return XDP_DROP;
	if (!test_pass_done) {
		if (prep_packet(ctx)) {
			struct xdp_record rec = { .type = REC_TYPE_PASS_THROW };

			bpf_ringbuf_output(&ringbuf, &rec, sizeof(rec), BPF_RB_FORCE_WAKEUP);
		}
		return XDP_PASS;
	}
	if (!test_tx_done) {
		void *data_end = (void *)(long)ctx->data_end;
		void *data = (void *)(long)ctx->data;
		struct pinginfo *pinginfo = NULL;
		struct ethhdr *eth = data;
		struct icmphdr *icmph;
		struct iphdr *iph;
		__u64 recvtime;
		__be32 raddr;
		__be16 seq;
		int ret;
		__u8 i;

		ret = icmp_check(ctx, ICMP_ECHOREPLY);

		if (ret != XDP_TX)
			return ret;

		iph = data + sizeof(*eth);
		icmph = data + sizeof(*eth) + sizeof(*iph);
		raddr = iph->saddr;

		/* Record time reply received. */
		recvtime = bpf_ktime_get_ns();
		pinginfo = bpf_map_lookup_elem(&ping_map, &raddr);
		if (!pinginfo || pinginfo->seq != icmph->un.echo.sequence)
			return XDP_PASS;

		if (pinginfo->start) {
#pragma clang loop unroll(full)
			for (i = 0; i < XDPING_MAX_COUNT; i++) {
				if (pinginfo->times[i] == 0)
					break;
			}
			/* verifier is fussy here... */
			if (i < XDPING_MAX_COUNT) {
				pinginfo->times[i] = recvtime -
						     pinginfo->start;
				pinginfo->start = 0;
				i++;
			}
			/* No more space for values? */
			if (i == pinginfo->count || i == XDPING_MAX_COUNT)
				return XDP_PASS;
		}

		/* Now convert reply back into echo request. */
		swap_src_dst_mac(data);
		iph->saddr = iph->daddr;
		iph->daddr = raddr;
		icmph->type = ICMP_ECHO;
		seq = bpf_htons(bpf_ntohs(icmph->un.echo.sequence) + 1);
		icmph->un.echo.sequence = seq;
		icmph->checksum = 0;
		icmph->checksum = ipv4_csum(icmph, ICMP_ECHO_LEN);

		pinginfo->seq = seq;
		pinginfo->start = bpf_ktime_get_ns();

		return XDP_TX;
	}
	if (!test_redirect_done) {
		if (bpf_map_update_elem(&ctx_map, &ctx, &ctx, 0))
			return XDP_PASS;
		bpf_redirect(42, 0);
	}
	return XDP_PASS;
}

SEC("xdp")
int xdp_generic(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *e;

	if (xdp_generic_done)
		return XDP_PASS;
	if (data + sizeof(*e) > data_end)
		return XDP_PASS;
	e = data;
	data += sizeof(*e);
	if (data + sizeof(key) > data_end)
		return XDP_PASS;
	if (equal_source(e->h_source, source) && *(u64 *)data == key) {
		struct xdp_record rec = { .type = REC_TYPE_PASS_CATCH };

		xdp_generic_done = true;
		bpf_ringbuf_output(&ringbuf, &rec, sizeof(rec), BPF_RB_FORCE_WAKEUP);
		return XDP_DROP;
	}
	return XDP_PASS;
}

SEC("tp_btf/xdp_exception")
int BPF_PROG(xdp_exception, const struct net_device *dev, const struct bpf_prog *xdp, u32 act)
{
	struct xdp_record rec = {
		.type = REC_TYPE_EXCEPTION,
		.data = act,
	};

	if (!trace_exception)
		return 0;
	bpf_ringbuf_output(&ringbuf, &rec, sizeof(rec), BPF_RB_FORCE_WAKEUP);
	return 0;
}

SEC("fentry/bpf_warn_invalid_xdp_action")
int BPF_PROG(xdp_invalid, const struct net_device *dev, const struct bpf_prog *xdp, u32 act)
{
	struct xdp_record rec = {
		.type = REC_TYPE_INVALID,
		.data = act,
	};

	if (!trace_invalid)
		return 0;
	bpf_ringbuf_output(&ringbuf, &rec, sizeof(rec), BPF_RB_FORCE_WAKEUP);
	return 0;
}

SEC("fentry/xdp_do_redirect")
int BPF_PROG(xdp_redirect, struct net_device *dev, struct xdp_buff *xdp, struct bpf_prog *xdp_prog)
{
	struct xdp_record rec = {
		.type = REC_TYPE_REDIRECT,
	};
	__u64 *v;

	if (!trace_redirect)
		return 0;
	v = bpf_map_lookup_elem(&ctx_map, &xdp);
	if (!v)
		return 0;
	bpf_ringbuf_output(&ringbuf, &rec, sizeof(rec), BPF_RB_FORCE_WAKEUP);
	return 0;
}

char _license[] SEC("license") = "GPL";
