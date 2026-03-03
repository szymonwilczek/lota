// SPDX-License-Identifier: MIT

package types

// TPM signature algorithm identifiers (TPM2_ALG_*)
// Used for quote signature scheme selection.
const (
	TPMAlgRSASSA uint16 = 0x0014
	TPMAlgRSAPSS uint16 = 0x0016
	TPMAlgSHA1   uint16 = 0x0004
	TPMAlgSHA256 uint16 = 0x000B
	TPMAlgSHA384 uint16 = 0x000C
	TPMAlgSHA512 uint16 = 0x000D
)
