// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
package verify

import (
	"fmt"
	"testing"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

// A certificate that does not certify the key the quote was signed with is
// not a signature failure. The signature verified; the key it verified
// against is not the one this device was issued a certificate for.
//
// The two have opposite answers. A failing signature means a corrupt or forged
// quote and the host is suspect; a certificate that names another key means
// the host has to re-enroll, which is what a TPM clear leaves behind.
func TestCertificateVerdict_KeyMismatchIsNotASignatureFailure(t *testing.T) {
	err := fmt.Errorf("AIK certificate verification failed: %w",
		store.ErrCertificateKeyMatch)

	if got := certificateVerdict(err); got != types.VerifyIdentityFail {
		t.Errorf("a certificate naming another key was reported as %s",
			types.VerifyResultString(got))
	}
}

// Everything else that stops a report before its key is authenticated keeps
// the verdict it had.
// Widening the new one would trade one collapsed bucket for another.
func TestCertificateVerdict_OtherCertificateFailuresStay(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"expired", store.ErrCertificateExpired},
		{"not yet valid", store.ErrCertificateNotYet},
		{"chain does not verify", store.ErrCertificateChain},
		{"no trusted anchors", store.ErrNoTrustedCAs},
	} {
		if got := certificateVerdict(tc.err); got != types.VerifySigFail {
			t.Errorf("%s: reported as %s, expected sig_fail",
				tc.name, types.VerifyResultString(got))
		}
	}
}

// The wire code has to render as something an operator can act on,
// and the agent is the only party that can act on this one.
func TestIdentityFail_IsNamed(t *testing.T) {
	s := types.VerifyResultString(types.VerifyIdentityFail)
	if s == "" || s == fmt.Sprintf("unknown_%d", types.VerifyIdentityFail) {
		t.Errorf("the identity verdict has no name: %q", s)
	}
}
