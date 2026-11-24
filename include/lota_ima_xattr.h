/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Predicate over a security.ima xattr blob.
 *
 * A bare digest can be recomputed by an offline attacker after a swap, a
 * signature cannot.
 */
#ifndef LOTA_IMA_XATTR_H
#define LOTA_IMA_XATTR_H

#include <stddef.h>
#include <stdint.h>

/* Leading type byte, from enum evm_ima_xattr_type in the kernel */
#define LOTA_IMA_XATTR_DIGSIG 0x03 /* EVM_IMA_XATTR_DIGSIG */
#define LOTA_IMA_XATTR_PORTABLE_DIGSIG 0x05 /* EVM_XATTR_PORTABLE_DIGSIG */
#define LOTA_IMA_XATTR_VERITY_DIGSIG 0x06 /* IMA_VERITY_DIGSIG */

/**
 * lota_ima_xattr_is_signature() - Test whether a security.ima blob is signed.
 * @xattr: blob, may be NULL.
 * @len: bytes in @xattr.
 *
 * The kernel's xattr_verify() has no case for the portable type, which belongs
 * to EVM.
 *
 * Return: 1 for a DIGSIG, portable DIGSIG or verity DIGSIG, 0 otherwise.
 */
static inline int lota_ima_xattr_is_signature(const uint8_t *xattr, size_t len)
{
	if (!xattr || len < 1)
		return 0;
	return xattr[0] == LOTA_IMA_XATTR_DIGSIG ||
	       xattr[0] == LOTA_IMA_XATTR_PORTABLE_DIGSIG ||
	       xattr[0] == LOTA_IMA_XATTR_VERITY_DIGSIG;
}

#endif /* LOTA_IMA_XATTR_H */
