// SPDX-License-Identifier: MIT

package types

// TPM signature algorithm identifiers (TPM2_ALG_*)
// Used for quote signature scheme selection.
const (
	TPMAlgRSASSA uint16 = 0x0014
	TPMAlgRSAPSS uint16 = 0x0016
)
