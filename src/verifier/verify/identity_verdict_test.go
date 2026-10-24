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

// Nor is a certificate outside its validity window: AIK certificates carry
// a TTL, so every long-lived host expires, and the answer is re-enrolment,
// not distrust.
func TestCertificateVerdict_ValidityWindowIsNotASignatureFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"expired", store.ErrCertificateExpired},
		{"not yet valid", store.ErrCertificateNotYet},
	} {
		err := fmt.Errorf("AIK certificate verification failed: %w",
			tc.err)

		if got := certificateVerdict(err); got == types.VerifySigFail {
			t.Errorf("%s: reported as %s, which names a corrupt or forged quote",
				tc.name, types.VerifyResultString(got))
		}
	}
}

// Only signature, parse and trust-configuration failures stay sig_fail.
// Widening either verdict above to cover them would trade one collapsed
// bucket for another.
func TestCertificateVerdict_OtherCertificateFailuresStay(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"unparseable certificate", store.ErrInvalidCertificate},
		{"chain does not verify", store.ErrCertificateChain},
		{"no trusted anchors", store.ErrNoTrustedCAs},
	} {
		if got := certificateVerdict(tc.err); got != types.VerifySigFail {
			t.Errorf("%s: reported as %s, expected sig_fail",
				tc.name, types.VerifyResultString(got))
		}
	}
}

// The verdict's name is all the host sees; the verifier's log is not its own.
func TestCertificateValidity_IsNamed(t *testing.T) {
	s := types.VerifyResultString(types.VerifyCertificateValidity)
	if s == "" || s == fmt.Sprintf("unknown_%d", types.VerifyCertificateValidity) {
		t.Errorf("the certificate-validity verdict has no name: %q", s)
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
