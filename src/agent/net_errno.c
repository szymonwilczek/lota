/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Names for the LOTA-private transport codes in net.h. Apart from net.c
 * so callers link without OpenSSL, as tpm_errno.c is apart from tpm.c.
 */

#include <string.h>

#include "net.h"

const char *net_err_name(int err)
{
	int code = err < 0 ? -err : err;

	switch (code) {
	case LOTA_ERR_NET_PEER_CLOSED:
		return "the peer closed the connection before the exchange "
		       "finished";
	case LOTA_ERR_NET_PEER_GONE:
		return "the peer went away without closing the connection";
	case LOTA_ERR_NET_TLS:
		return "TLS protocol failure on an established connection";
	case LOTA_ERR_NET_TLS_HANDSHAKE:
		return "the TLS handshake did not complete";
	case LOTA_ERR_NET_TLS_CERT:
		return "the peer's TLS certificate was not accepted";
	case LOTA_ERR_NET_TLS_PIN:
		return "the peer's TLS certificate is not the pinned one";
	default:
		return NULL;
	}
}

int net_err_is_tls(int err)
{
	int code = err < 0 ? -err : err;

	return code == LOTA_ERR_NET_TLS || code == LOTA_ERR_NET_TLS_HANDSHAKE ||
	       code == LOTA_ERR_NET_TLS_CERT || code == LOTA_ERR_NET_TLS_PIN;
}

const char *net_strerror(int err)
{
	const char *name = net_err_name(err);

	return name ? name : strerror(err < 0 ? -err : err);
}
