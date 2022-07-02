// SPDX-License-Identifier: GPL-2.0
#ifndef __XDP_FEATURES_TEST_H__
#define __XDP_FEATURES_TEST_H__

enum xdp_record_type {
	REC_TYPE_PASS_THROW,
	REC_TYPE_PASS_CATCH,
	REC_TYPE_EXCEPTION,
	REC_TYPE_INVALID,
	REC_TYPE_REDIRECT,
};

struct xdp_record {
	enum xdp_record_type type;
	unsigned int data;
};

#endif
