// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"encoding/binary"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

// A report that carries no AIK certificate must be rejected: the
// certificate chain is the verifier's sole AIK trust anchor, so an agent
// that has not enrolled with the attestation CA cannot attest.
func TestRequireCert_RejectsReportWithoutAIKCertificate(t *testing.T) {
	aikStore := newCertStore(t)
	verifier := createTestVerifier(t, aikStore)

	clientID := "no-cert-client"
	challenge, err := verifier.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}

	pcr14 := [32]byte{}
	reportData := createValidReport(t, clientID, challenge.Nonce, pcr14)

	// Zero the aik_cert_size field so the report no longer carries a
	// certificate, leaving the AIK unauthenticated.
	aikCertSizeOff := 16 + types.PCRCount*types.HashSize + 4 +
		types.MaxSigSize + 2 + types.MaxAttestSize + 2 +
		types.MaxAIKPubSize + 2 + types.MaxAIKCertSize
	binary.LittleEndian.PutUint16(reportData[aikCertSizeOff:aikCertSizeOff+2], 0)

	result, verr := verifier.VerifyReport(clientID, reportData)
	if verr == nil {
		t.Fatal("expected verification to fail without an AIK certificate")
	}
	if result == nil || result.Result != types.VerifySigFail {
		t.Fatalf("expected VerifySigFail, got %+v (err=%v)", result, verr)
	}
}
