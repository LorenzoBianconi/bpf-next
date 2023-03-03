// SPDX-License-Identifier: GPL-2.0-only

#include "netlink.h"
#include "common.h"
#include "bitset.h"

const struct nla_policy ethnl_xdp_features_get_policy[] = {
	[ETHTOOL_A_XDP_FEATURES_HEADER] = NLA_POLICY_NESTED(ethnl_header_policy),
};

struct xdp_feature_req_info {
	struct ethnl_req_info base;
};

#define XDP_FEATURES_REPDATA(__reply_base)	\
	container_of(__reply_base, struct xdp_feature_reply_data, base)

struct xdp_feature_reply_data {
	struct ethnl_reply_data base;
	u32 features[ETHTOOL_XDP_FEATURES_WORDS];
};

static int xdp_features_prepare_data(const struct ethnl_req_info *req_base,
				     struct ethnl_reply_data *reply_base,
				     struct genl_info *info)
{
	struct xdp_feature_reply_data *data = XDP_FEATURES_REPDATA(reply_base);
	struct net_device *dev = reply_base->dev;

	BUILD_BUG_ON(ETHTOOL_XDP_FEATURES_WORDS != 1);
	data->features[0] = dev->xdp_features;

	return 0;
}

static int xdp_features_reply_size(const struct ethnl_req_info *req_base,
				   const struct ethnl_reply_data *reply_base)
{
	bool compact = req_base->flags & ETHTOOL_FLAG_COMPACT_BITSETS;
	const struct xdp_feature_reply_data *data;

	data = XDP_FEATURES_REPDATA(reply_base);
	return ethnl_bitset32_size(data->features, NULL, __NETDEV_XDP_ACT_BIT_MAX,
				   xdp_features_strings, compact);
}

static int xdp_features_fill_reply(struct sk_buff *skb,
				   const struct ethnl_req_info *req_base,
				   const struct ethnl_reply_data *reply_base)
{
	bool compact = req_base->flags & ETHTOOL_FLAG_COMPACT_BITSETS;
	const struct xdp_feature_reply_data *data;

	data = XDP_FEATURES_REPDATA(reply_base);
	return ethnl_put_bitset32(skb, ETHTOOL_A_XDP_FEATURES_DATA,
				  data->features, NULL, __NETDEV_XDP_ACT_BIT_MAX,
				  xdp_features_strings, compact);
}

const struct ethnl_request_ops ethnl_xdp_request_ops = {
	.request_cmd		= ETHTOOL_MSG_XDP_FEATURES_GET,
	.reply_cmd		= ETHTOOL_MSG_XDP_FEATURES_GET_REPLY,
	.hdr_attr		= ETHTOOL_A_XDP_FEATURES_HEADER,
	.req_info_size		= sizeof(struct xdp_feature_req_info),
	.reply_data_size	= sizeof(struct xdp_feature_reply_data),
	.prepare_data		= xdp_features_prepare_data,
	.reply_size		= xdp_features_reply_size,
	.fill_reply		= xdp_features_fill_reply,
};
