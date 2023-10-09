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
#include <net/ip.h>
#include <linux/ipv6.h>
#include <net/ip6_route.h>
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

static int bpf_xdp_flow_offload_ip(struct flow_offload_tuple_rhash *tuplehash,
				   void *nethdr)
{
	enum flow_offload_tuple_dir dir = tuplehash->tuple.dir;
	struct iphdr *iph = nethdr;
	unsigned int thoff = iph->ihl * 4;
	struct flow_offload *flow;

	flow = container_of(tuplehash, struct flow_offload, tuplehash[dir]);
	if (!nf_flow_dst_check(&tuplehash->tuple)) {
		flow_offload_teardown(flow);
		return -EINVAL;
	}

	if (nf_flow_state_check(flow, iph->protocol, nethdr, thoff))
		return -EINVAL;

	/* fragmented IP or IP options */
	if (ip_is_fragment(iph) || thoff != sizeof(*iph))
		return -EINVAL;

	if (iph->ttl <= 1)
		return -EINVAL;

	nf_flow_nat_ip(flow, NULL, thoff, dir, iph);
	ip_decrease_ttl(iph);

	return 0;
}

static int
bpf_xdp_flow_offload_ipv6(struct flow_offload_tuple_rhash *tuplehash,
			  void *nethdr)
{
	enum flow_offload_tuple_dir dir = tuplehash->tuple.dir;
	struct ipv6hdr *ip6h = nethdr;
	struct flow_offload *flow;

	flow = container_of(tuplehash, struct flow_offload, tuplehash[dir]);
	if (!nf_flow_dst_check(&tuplehash->tuple)) {
		flow_offload_teardown(flow);
		return -EINVAL;
	}

	if (nf_flow_state_check(flow, ip6h->nexthdr, nethdr, sizeof(*ip6h)))
		return -EINVAL;

	if (ip6h->hop_limit <= 1)
		return -EINVAL;

	nf_flow_nat_ipv6(flow, NULL, dir, ip6h);
	ip6h->hop_limit--;

	return 0;
}

__bpf_kfunc int
bpf_xdp_flow_offload_inet(struct xdp_md *xdp_ctx,
			  struct flow_offload_tuple_rhash *tuplehash)
{
	struct xdp_buff *xdp = (struct xdp_buff *)xdp_ctx;
	struct ethhdr *eth = xdp->data;
	void *nethdr = xdp->data + sizeof(*eth);

	if (!tuplehash)
		return -EINVAL;

	switch (eth->h_proto) {
	case htons(ETH_P_IP):
		return bpf_xdp_flow_offload_ip(tuplehash, nethdr);
	case htons(ETH_P_IPV6):
		return bpf_xdp_flow_offload_ipv6(tuplehash, nethdr);
	default:
		return -EINVAL;
	}
}

static int
bpf_xdp_flow_offload_xmit_neigh(struct ethhdr *eth,
				struct flow_offload_tuple_rhash *tuplehash)
{
	enum flow_offload_tuple_dir dir = tuplehash->tuple.dir;
	struct flow_offload *flow;
	struct neighbour *neigh;
	struct net_device *dev;

	flow = container_of(tuplehash, struct flow_offload, tuplehash[dir]);
	switch (tuplehash->tuple.l3proto) {
	case AF_INET: {
		struct rtable *rt;
		__be32 nexthop;

		rt = (struct rtable *)tuplehash->tuple.dst_cache;
		dev = rt->dst.dev;
		nexthop = rt_nexthop(rt,
				     flow->tuplehash[!dir].tuple.src_v4.s_addr);
		neigh = __ipv4_neigh_lookup_noref(dev, nexthop);
		break;
	}
	case AF_INET6: {
		const struct in6_addr *nexthop;
		struct rt6_info *rt;

		rt = (struct rt6_info *)tuplehash->tuple.dst_cache;
		dev = rt->dst.dev;
		nexthop = rt6_nexthop(rt, &flow->tuplehash[!dir].tuple.src_v6);
		neigh = __ipv6_neigh_lookup_noref_stub(dev, nexthop);
		break;
	}
	default:
		return -EINVAL;
	}

	if (!neigh)
		return -EINVAL;


	memcpy(eth->h_dest, neigh->ha, ETH_ALEN);
	memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);

	return dev->ifindex;
}

__bpf_kfunc int
bpf_xdp_flow_offload_xmit(struct xdp_md *xdp_ctx,
			  struct flow_offload_tuple_rhash *tuplehash)
{
	struct xdp_buff *xdp = (struct xdp_buff *)xdp_ctx;
	struct ethhdr *eth = xdp->data;

	if (!tuplehash)
		return -EINVAL;

	switch (tuplehash->tuple.xmit_type) {
	case FLOW_OFFLOAD_XMIT_NEIGH:
		return bpf_xdp_flow_offload_xmit_neigh(eth, tuplehash);
	case FLOW_OFFLOAD_XMIT_DIRECT:
		memcpy(eth->h_dest, tuplehash->tuple.out.h_dest, ETH_ALEN);
		memcpy(eth->h_source, tuplehash->tuple.out.h_source, ETH_ALEN);
		return tuplehash->tuple.out.ifidx;
	case FLOW_OFFLOAD_XMIT_XFRM: /* not supported yet */
	default:
		return -EINVAL;
	}
}

__diag_pop()

BTF_SET8_START(nf_ft_kfunc_set)
BTF_ID_FLAGS(func, bpf_xdp_flow_offload_lookup)
BTF_ID_FLAGS(func, bpf_xdp_flow_offload_inet)
BTF_ID_FLAGS(func, bpf_xdp_flow_offload_xmit)
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
