// SPDX-License-Identifier: MIT
// LOTA Verifier - Fuzz Tests for store package (certificates, client ID, hardware ID)

package store

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// fuzzes validateClientID path traversal protection
func FuzzValidateClientID(f *testing.F) {
	// seed 1: valid hex client ID
	f.Add("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	// seed 2: path traversal attempt
	f.Add("../../../etc/passwd")
	// seed 3: backslash path traversal
	f.Add("..\\..\\system32")
	// seed 4: embedded NUL
	f.Add("abc\x00def")
	// seed 5: empty
	f.Add("")
	// seed 6: just dots
	f.Add("..")
	// seed 7: slash in middle
	f.Add("abc/def")

	f.Fuzz(func(t *testing.T, id string) {
		err := validateClientID(id)

		// must reject empty
		if id == "" && err == nil {
			t.Error("accepted empty client ID")
		}

		// must reject path separators
		for _, c := range id {
			if c == '/' || c == '\\' || c == 0 {
				if err == nil {
					t.Errorf("accepted client ID with dangerous char %q: %q", c, id)
				}
				return
			}
		}

		// must reject ".."
		if len(id) >= 2 {
			for i := 0; i < len(id)-1; i++ {
				if id[i] == '.' && id[i+1] == '.' {
					if err == nil {
						t.Errorf("accepted client ID with '..': %q", id)
					}
					return
				}
			}
		}
	})
}

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

		// public key must be non-nil
		if cert.PublicKey == nil {
			t.Error("parsed certificate has nil public key")
		}
	})
}

// fuzzes X.509 EK certificate parsing with TCG OID check
func FuzzParseEKCertificate(f *testing.F) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "test-ek"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 23, 133, 8, 1}},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)

	// cert without TCG OID
	tmplNoOID := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-no-oid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certNoOID, _ := x509.CreateCertificate(rand.Reader, tmplNoOID, tmplNoOID, &key.PublicKey, key)

	f.Add(certDER)
	f.Add(certNoOID)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return
		}

		// check for TCG EK OID the same way verifyEKCertificate does
		found := false
		for _, oid := range cert.UnknownExtKeyUsage {
			if oid.Equal(asn1.ObjectIdentifier{2, 23, 133, 8, 1}) {
				found = true
				break
			}
		}
		_ = found
	})
}
