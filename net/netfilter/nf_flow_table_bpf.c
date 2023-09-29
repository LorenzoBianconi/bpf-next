// SPDX-License-Identifier: GPL-2.0-only
/* Unstable Flow Table Helpers for XDP hook
 *
 * These are called from the XDP programs.
 * Note that it is allowed to break compatibility for these functions since
 * the interface they are exposed through to BPF programs is explicitly
 * unstable.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/rhashtable.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <net/netfilter/nf_flow_table.h>
#include <linux/bpf_verifier.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <net/xdp.h>

__diag_push();
__diag_ignore_all("-Wmissing-prototypes",
		  "Global functions as their definitions will be in nf_flow_table BTF");

static bool bpf_xdp_flow_hook_is_allowed(nf_hookfn hook, __be16 proto)
{
#if IS_BUILTIN(CONFIG_NF_FLOW_TABLE_INET) || IS_MODULE(CONFIG_NF_FLOW_TABLE_INET)
	if (hook == nf_flow_offload_inet_hook)
		return true;
#endif
	if ((proto == htons(ETH_P_IP) && hook == nf_flow_offload_ip_hook) ||
	    (proto == htons(ETH_P_IPV6) && hook == nf_flow_offload_ipv6_hook))
		return true;

	return false;
}

static struct flow_offload_tuple_rhash *
bpf_xdp_flow_offload_tuple_lookup(struct net_device *dev,
				  struct flow_offload_tuple *tuple,
				  __be16 proto)
{
	struct nf_hook_entries *e = rcu_dereference(dev->nf_hooks_ingress);
	int i;

	if (!e)
		return ERR_PTR(-ENOENT);

	for (i = 0; i < e->num_hook_entries; i++) {
		struct flow_offload_tuple_rhash *tuplehash;
		struct flow_offload *flow;

		if (!bpf_xdp_flow_hook_is_allowed(e->hooks[i].hook, proto))
			continue;

		tuplehash = flow_offload_lookup(e->hooks[i].priv, tuple);
		if (!tuplehash)
			continue;

		flow = container_of(tuplehash, struct flow_offload,
				    tuplehash[tuplehash->tuple.dir]);
		flow_offload_refresh(e->hooks[i].priv, flow, false);

		return tuplehash;
	}

	return ERR_PTR(-ENOENT);
}

__bpf_kfunc struct flow_offload_tuple_rhash *
bpf_xdp_flow_offload_lookup(struct xdp_md *ctx,
			    struct bpf_fib_lookup *fib_tuple,
			    u32 fib_tuple__sz)
{
	struct xdp_buff *xdp = (struct xdp_buff *)ctx;
	struct flow_offload_tuple tuple = {
		.iifidx = fib_tuple->ifindex,
		.l3proto = fib_tuple->family,
		.l4proto = fib_tuple->l4_protocol,
		.src_port = fib_tuple->sport,
		.dst_port = fib_tuple->dport,
	};
	__be16 proto;

	switch (fib_tuple->family) {
	case AF_INET:
		tuple.src_v4.s_addr = fib_tuple->ipv4_src;
		tuple.dst_v4.s_addr = fib_tuple->ipv4_dst;
		proto = htons(ETH_P_IP);
		break;
	case AF_INET6:
		tuple.src_v6 = *(struct in6_addr *)&fib_tuple->ipv6_src;
		tuple.dst_v6 = *(struct in6_addr *)&fib_tuple->ipv6_dst;
		proto = htons(ETH_P_IPV6);
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	return bpf_xdp_flow_offload_tuple_lookup(xdp->rxq->dev, &tuple, proto);
}

__diag_pop()

BTF_SET8_START(nf_ft_kfunc_set)
BTF_ID_FLAGS(func, bpf_xdp_flow_offload_lookup)
BTF_SET8_END(nf_ft_kfunc_set)

static const struct btf_kfunc_id_set nf_flow_offload_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &nf_ft_kfunc_set,
};

int nf_flow_offload_register_bpf(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_XDP,
					 &nf_flow_offload_kfunc_set);
}
EXPORT_SYMBOL_GPL(nf_flow_offload_register_bpf);
