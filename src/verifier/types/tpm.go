// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package types

// TPM2_ALG_* identifiers of the quote signature scheme and its hash.
const (
	TPMAlgRSASSA uint16 = 0x0014
	TPMAlgRSAPSS uint16 = 0x0016
	TPMAlgSHA1   uint16 = 0x0004
	TPMAlgSHA256 uint16 = 0x000B
	TPMAlgSHA384 uint16 = 0x000C
	TPMAlgSHA512 uint16 = 0x000D
)
