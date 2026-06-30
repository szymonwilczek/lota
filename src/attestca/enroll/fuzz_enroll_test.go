// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package enroll

import (
	"testing"

	"github.com/szymonwilczek/lota/attestca/internal/tpmtest"
)

// FuzzServiceBegin drives the enrollment entry point with arbitrary client
// blobs: the EK certificate DER and the AIK TPMT_PUBLIC, both from an
// untrusted peer. Begin must never panic and must return a challenge exactly
// when it returns no error.
func FuzzServiceBegin(f *testing.F) {
	svc, root := newTestService(f)
	ek := tpmtest.NewEKCert(f, root)
	aikTPMT, _ := tpmtest.AIKTemplate(f)

	f.Add(aikTPMT, ek.CertDER, true)
	f.Add([]byte("not-a-tpmt-public"), ek.CertDER, true)
	f.Add(aikTPMT, []byte{}, false)
	f.Add([]byte{}, []byte{}, false)

	f.Fuzz(func(t *testing.T, aikTPMTPublic, ekFuzz []byte, useValidEK bool) {
		// Random EK bytes die at the certificate-chain gate, so the AIK
		// validation and credential-make path behind it never runs.
		// Driving the real EK certificate for part of the space lets
		// mutation of the AIK TPMT_PUBLIC reach that deeper logic.
		ekCertDER := ekFuzz
		if useValidEK {
			ekCertDER = ek.CertDER
		}

		ch, err := svc.Begin(ekCertDER, aikTPMTPublic)
		if (err == nil) != (ch != nil) {
			t.Fatalf("contract violated: err=%v ch=%v", err, ch)
		}
		if err == nil {
			// usable credential-activation challenge must carry both the
			// credential blob and the encrypted secret, or the client can
			// never prove EK/AIK co-residency
			if len(ch.CredentialBlob) == 0 || len(ch.EncryptedSecret) == 0 {
				t.Fatalf("Begin succeeded without credential material: blob=%d secret=%d",
					len(ch.CredentialBlob), len(ch.EncryptedSecret))
			}
		}
	})
}
