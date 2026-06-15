// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package ca

import (
	"testing"
	"time"
)

// FuzzVerifyEKCertificate drives the untrusted EK-certificate parser and
// chain verifier with arbitrary DER. A client hands this to the CA during
// enrollment, so it must never panic and must return a certificate exactly
// when it returns no error.
func FuzzVerifyEKCertificate(f *testing.F) {
	root := makeRoot(f, "ek-root")
	is := newTestIssuer(f, root)
	validDER, _ := makeEKCert(f, root, nil)

	f.Add(validDER)
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})

	f.Fuzz(func(t *testing.T, der []byte) {
		cert, err := is.VerifyEKCertificate(der, time.Now())
		if (err == nil) != (cert != nil) {
			t.Fatalf("contract violated: err=%v cert=%v", err, cert)
		}
	})
}

// FuzzParseEKBundleManifest feeds arbitrary bytes to the EK-root bundle
// manifest parser. It must never panic and must only return entries when it
// returns no error.
func FuzzParseEKBundleManifest(f *testing.F) {
	f.Add([]byte("# pinned roots\n" +
		"0000000000000000000000000000000000000000000000000000000000000000 root.pem Infineon\n"))
	f.Add([]byte(""))
	f.Add([]byte("deadbeef short.pem"))

	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := parseEKBundleManifest(data)
		if err != nil && entries != nil {
			t.Fatalf("entries returned alongside error: %v", err)
		}
	})
}
