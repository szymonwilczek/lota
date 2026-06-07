// SPDX-License-Identifier: MIT
// LOTA Verifier - Fuzz tests for RSA public key parser

package verify

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"
)

func FuzzParseRSAPublicKey(f *testing.F) {
	// seed: valid 2048-bit RSA public key in PKIX/SPKI DER
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(der)

	// seed: PKCS#1 format (must be rejected)
	pkcs1 := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	f.Add(pkcs1)

	// seed: garbage
	f.Add([]byte{0x30, 0x82, 0x01, 0x22})

	f.Fuzz(func(t *testing.T, data []byte) {
		pub, err := ParseRSAPublicKey(data)
		if err != nil {
			if pub != nil {
				t.Fatal("ParseRSAPublicKey returned non-nil key with error")
			}
			return
		}
		if pub == nil {
			t.Fatal("ParseRSAPublicKey returned nil without error")
		}
		if pub.N.BitLen() < 2048 {
			t.Fatalf("accepted key with %d bits, minimum 2048", pub.N.BitLen())
		}
	})
}
