// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <linux/xdp_features.h>

#include "bpf_util.h"
#include "xdp_features_test.h"
#include "xdp_features.skel.h"

static const char *xdp_features_str[XDP_FEATURES_COUNT] = {
	[XDP_F_ABORTED_BIT]         = "xdp-aborted",
	[XDP_F_DROP_BIT]            = "xdp-drop",
	[XDP_F_PASS_BIT]            = "xdp-pass",
	[XDP_F_TX_BIT]              = "xdp-tx",
	[XDP_F_REDIRECT_BIT]        = "xdp-redirect",
	[XDP_F_REDIRECT_TARGET_BIT] = "xdp-redirect-target",
	[XDP_F_SOCK_ZEROCOPY_BIT]   = "xdp-zerocopy",
	[XDP_F_HW_OFFLOAD_BIT]      = "xdp-hw-offload",
	[XDP_F_TX_LOCK_BIT]         = "xdp-tx-lock",
};

struct net_device_attr {
	int ifindex;
	__u32 xdp_features[XDP_FEATURES_WORDS];
	bool redirect_target_runtime;
};

#define RED(str) "\033[0;31m" str "\033[0m"
#define GRN(str) "\033[0;32m" str "\033[0m"
#define YLW(str) "\033[0;33m" str "\033[0m"

static void report(__u32 *detected_features, __u32 *reported_features, bool redirect_target_runtime)
{
	int bits[] = { XDP_F_ABORTED_BIT, XDP_F_DROP_BIT, XDP_F_PASS_BIT, XDP_F_TX_BIT,
		       XDP_F_REDIRECT_BIT, XDP_F_REDIRECT_TARGET_BIT };
	int i;

	printf("XDP Compliance Summary:\n");
	for (i = 0; i < ARRAY_SIZE(bits); i++) {
		bool warn_rdt = redirect_target_runtime && bits[i] == XDP_F_REDIRECT_TARGET_BIT;
		bool r = XDP_FEATURES_BIT_IS_SET(reported_features, bits[i]);
		bool d = XDP_FEATURES_BIT_IS_SET(detected_features, bits[i]);
		const char *s = "????";

		if (r) {
			s = d ? (warn_rdt ? YLW("WARN") : GRN("SUPP")) : RED("FAIL");
		} else if (d) {
			printf("!!! Fix driver to report detected feature %s\n",
			       xdp_features_str[bits[i]]);
			s = GRN("SUPP");
		}
		printf(" - [%s] %s\n", s, warn_rdt ?
		       "xdp-redirect-target - Needs XDP program to be loaded on device :^(" :
		       xdp_features_str[bits[i]]);
	}
}

int main(int argc, char *argv[])
{
	__u32 bef_xdp_flags[XDP_FEATURES_WORDS] = {}, aft_xdp_flags[XDP_FEATURES_WORDS] = {};
	struct xdp_features *skel;
	int ifindex, ret;
	__u32 prog_id;

	ret = libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	if (ret < 0) {
		fprintf(stderr, "Failed to set libbpf_set_strict_mode: %m\n");
		return 1;
	}

	report(&(__u32){
		XDP_FEATURES_FIELD_FLAG(XDP_F_REDIRECT_TARGET_BIT) |
		XDP_FEATURES_FIELD_FLAG(XDP_F_REDIRECT_BIT) |
		XDP_FEATURES_FIELD_FLAG(XDP_F_TX_BIT) |
		XDP_FEATURES_FIELD_FLAG(XDP_F_PASS_BIT) |
		XDP_FEATURES_FIELD_FLAG(XDP_F_DROP_BIT) |
		XDP_FEATURES_FIELD_FLAG(XDP_F_ABORTED_BIT)
		},
	       &(__u32){
		XDP_FEATURES_FIELD_FLAG(XDP_F_REDIRECT_TARGET_BIT) |
		XDP_FEATURES_FIELD_FLAG(XDP_F_REDIRECT_BIT) |
		XDP_FEATURES_FIELD_FLAG(XDP_F_TX_BIT) |
		XDP_FEATURES_FIELD_FLAG(XDP_F_PASS_BIT) |
		XDP_FEATURES_FIELD_FLAG(XDP_F_DROP_BIT) |
		XDP_FEATURES_FIELD_FLAG(XDP_F_ABORTED_BIT)
		}, true);
	return 0;

	skel = xdp_features__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to do xdp_features__open_and_load: %m\n");
		return 1;
	}

	//
	ifindex = 0;
	//
	ret = bpf_xdp_query_id(ifindex, XDP_FLAGS_DRV_MODE, &prog_id);
	if (!ret) {
		fprintf(stderr, "Failed to test XDP compliance: prog (id: %d) loaded on device\n",
			prog_id);
		return 1;
	}

	ret = bpf_xdp_query_features(ifindex, bef_xdp_flags, ARRAY_SIZE(bef_xdp_flags));
	if (ret < 0) {
		fprintf(stderr, "Failed to query XDP features for ifindex %d: %m\n", ifindex);
		return 1;
	}

	ret = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_generic),
			     XDP_FLAGS_DRV_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
	if (ret < 0) {
		fprintf(stderr, "Failed to attach XDP program to ifindex %d: %m", ifindex);
		return 1;
	}

	ret = bpf_xdp_query_features(ifindex, aft_xdp_flags, ARRAY_SIZE(aft_xdp_flags));
	if (ret < 0) {
		fprintf(stderr, "Failed to query XDP features for ifindex %d: %m\n", ifindex);
		goto detach;
	}

detach:
	bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
	return 1;
}
