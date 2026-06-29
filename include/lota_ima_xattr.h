/* SPDX-License-Identifier: MIT
 * Copyright (C) 2026 Szymon Wilczek
 *
 * Shared predicate over a security.ima xattr blob.
 *
 * On filesystems without fs-verity (XFS, ZFS, ...) agent treats kernel IMA
 * appraisal as the equivalent immutability guarantee for its own binary:
 * under ima_appraise=enforce the kernel refuses to exec or read a file whose
 * content does not match its signed security.ima xattr.
 * Only signature variant binds the content to a key in the .ima keyring;
 * bare digest can be recomputed by an offline attacker after a swap and is
 * therefore never proof of immutability.
 */
#ifndef LOTA_IMA_XATTR_H
#define LOTA_IMA_XATTR_H

#include <stddef.h>
#include <stdint.h>

/*
 * Leading type byte of a security.ima xattr, mirroring the kernel's
 * enum evm_ima_xattr_type (security/integrity/integrity.h)
 */
#define LOTA_IMA_XATTR_DIGEST 0x01 /* unsigned SHA1 digest */
#define LOTA_IMA_XATTR_DIGSIG 0x03 /* EVM_IMA_XATTR_DIGSIG */
#define LOTA_IMA_XATTR_DIGEST_NG 0x04 /* unsigned, algorithm-tagged */
#define LOTA_IMA_XATTR_VERITY_DIGSIG 0x05 /* IMA_VERITY_DIGSIG */

/*
 * True when a security.ima xattr blob is a signature (DIGSIG or VERITY_DIGSIG):
 * kernel IMA appraisal in enforce mode would have refused to exec or read the
 * file unless its content matched the signed hash.
 * NULL or empty blob, bare digest, or an unknown leading byte is not a signature.
 */
static inline int lota_ima_xattr_is_signature(const uint8_t *xattr, size_t len)
{
	if (!xattr || len < 1)
		return 0;
	return xattr[0] == LOTA_IMA_XATTR_DIGSIG ||
	       xattr[0] == LOTA_IMA_XATTR_VERITY_DIGSIG;
}

#endif /* LOTA_IMA_XATTR_H */
