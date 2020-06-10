// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

static __u32 ingress_ifindex;

struct {
	__uint(type, BPF_MAP_TYPE_CPUMAP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct bpf_cpumap_val));
	__uint(max_entries, 4);
} cpu_map SEC(".maps");

SEC("xdp_redir")
int xdp_redir_prog(struct xdp_md *ctx)
{
	return bpf_redirect_map(&cpu_map, 1, 0);
}

SEC("xdp_dummy")
int xdp_dummy_prog(struct xdp_md *ctx)
{
	return XDP_PASS;
}

SEC("xdp_cpumap/dummy_cm")
int xdp_dummy_cm(struct xdp_md *ctx)
{
	char fmt[] = "devmap redirect: dev %u len %u\n";
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	unsigned int len = data_end - data;

	ingress_ifindex = ctx->ingress_ifindex;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
