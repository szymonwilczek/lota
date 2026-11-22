// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Fuzz Tests for store package (certificates, client ID, hardware ID)

package store

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// fuzzes ParseHardwareID hex decoding
func FuzzParseHardwareID(f *testing.F) {
	// seed 1: valid 32-byte hex
	f.Add("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	// seed 2: too short
	f.Add("abcdef")
	// seed 3: invalid hex chars
	f.Add("zzzzzzzz")
	// seed 4: empty
	f.Add("")
	// seed 5: odd length
	f.Add("abc")

	f.Fuzz(func(t *testing.T, hexStr string) {
		hwid, err := ParseHardwareID(hexStr)
		if err != nil {
			return
		}

		// round-trip must match
		formatted := FormatHardwareID(hwid)
		hwid2, err2 := ParseHardwareID(formatted)
		if err2 != nil {
			t.Errorf("round-trip failed: ParseHardwareID(%q) -> error: %v", formatted, err2)
		}
		if hwid != hwid2 {
			t.Error("round-trip produced different hardware ID")
		}
	})
}

// fuzzes the bans pagination cursor decoder (next_id comes from the HTTP API)
func FuzzDecodeBanCursor(f *testing.F) {
	// seed 1: well-formed cursor
	f.Add("1700000000000000000:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789:default")
	// seed 2: missing hardware ID and tenant
	f.Add("1700000000000000000")
	// seed 3: two-part cursor, one field short of the three required
	f.Add("1700000000000000000:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	// seed 4: too many colons
	f.Add("1:2:3:4")
	// seed 5: non-numeric timestamp
	f.Add("notanumber:abcdef:default")
	// seed 6: negative timestamp
	f.Add("-5:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789:default")
	// seed 7: empty
	f.Add("")

	f.Fuzz(func(t *testing.T, nextID string) {
		cur, err := DecodeBanCursor(nextID)
		if err != nil {
			return
		}

		// decoded cursor must survive an encode/decode round-trip
		// unchanged (the encoder is what the API hands back to clients)
		enc := EncodeBanCursor(BanEntry{
			Tenant:     cur.Tenant,
			HardwareID: cur.HardwareID,
			BannedAt:   cur.BannedAt,
		})
		cur2, err2 := DecodeBanCursor(enc)
		if err2 != nil {
			t.Errorf("re-decode of encoded cursor %q failed: %v", enc, err2)
		}
		if cur.HardwareID != cur2.HardwareID {
			t.Errorf("round-trip changed hardware ID: %x -> %x",
				cur.HardwareID, cur2.HardwareID)
		}
		if !cur.BannedAt.Equal(cur2.BannedAt) {
			t.Errorf("round-trip changed timestamp: %v -> %v",
				cur.BannedAt, cur2.BannedAt)
		}
		if cur.Tenant != cur2.Tenant {
			t.Errorf("round-trip changed tenant: %q -> %q",
				cur.Tenant, cur2.Tenant)
		}
	})
}

// fuzzes X.509 AIK certificate parsing (DER input from untrusted agent)
func FuzzParseAIKCertificate(f *testing.F) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-aik"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)

	f.Add(certDER)
	f.Add([]byte{0x30, 0x82, 0x00, 0x03}) // truncated ASN.1
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			if cert != nil {
				t.Error("ParseCertificate returned non-nil cert with error")
			}
			return
		}

		// x509 leaves PublicKey nil (and returns no error) for an unknown
		// key algorithm. An AIK cert is usable only with an RSA key, which
		// store's verifyAIKCertificate enforces via this same type assertion.
		// Mirror that guard: the assertion is always safe and a non-RSA key
		// is rejected, never dereferenced -- asserting cert.PublicKey != nil
		// here would test a contract x509.ParseCertificate does not make.
		if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
			return
		}
	})
}
