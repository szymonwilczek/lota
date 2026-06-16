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

	f.Add(ek.CertDER, aikTPMT)
	f.Add([]byte{}, []byte{})
	f.Add(ek.CertDER, []byte("not-a-tpmt-public"))

	f.Fuzz(func(t *testing.T, ekCertDER, aikTPMTPublic []byte) {
		ch, err := svc.Begin(ekCertDER, aikTPMTPublic)
		if (err == nil) != (ch != nil) {
			t.Fatalf("contract violated: err=%v ch=%v", err, ch)
		}
	})
}
