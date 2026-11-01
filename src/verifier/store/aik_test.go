// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - AIK store tests

package store

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// creates a test RSA key pair
func generateTestKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	return key
}

// creates a self-signed test certificate
func generateTestCertificate(t *testing.T, key *rsa.PrivateKey, isCA bool) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"LOTA Test"},
			CommonName:   "Test Certificate",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// creates a certificate signed by a CA
func generateSignedCertificate(t *testing.T, key *rsa.PrivateKey, ca *x509.Certificate, caKey *rsa.PrivateKey) []byte {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"LOTA Test"},
			CommonName:   "AIK Certificate",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create signed certificate: %v", err)
	}

	return certDER
}

func TestCertificateVerifier_NeedsTrustedCAs(t *testing.T) {
	cv, err := NewCertificateVerifier(nil, nil)
	if !errors.Is(err, ErrNoTrustedCAs) {
		t.Fatalf("Expected ErrNoTrustedCAs, got verifier=%v err=%v", cv, err)
	}
}

func TestCertificateVerifier_CertificateValidityWindow(t *testing.T) {
	expired := [2]time.Duration{-48 * time.Hour, -24 * time.Hour}
	notYet := [2]time.Duration{24 * time.Hour, 48 * time.Hour}
	valid := [2]time.Duration{-1 * time.Hour, 24 * time.Hour}

	tests := []struct {
		name string
		aik  [2]time.Duration
		ek   [2]time.Duration
		want error
	}{
		{"expired AIK", expired, valid, ErrCertificateExpired},
		{"future AIK", notYet, valid, ErrCertificateNotYet},
		{"expired EK", valid, expired, ErrCertificateExpired},
		{"future EK", valid, notYet, ErrCertificateNotYet},
	}

	caKey := generateTestKey(t)
	caCert := generateTestCertificate(t, caKey, true)
	caCertDER, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			caCertPath := filepath.Join(tempDir, "ca.pem")
			saveCertPEM(t, caCertPath, caCertDER)

			store, err := NewCertificateVerifier([]string{caCertPath}, nil)
			if err != nil {
				t.Fatalf("NewCertificateVerifier failed: %v", err)
			}

			aikKey := generateTestKey(t)
			aikDER := generateWindowedCertificate(t, aikKey, caCert, caKey, tt.aik, false)
			ekDER := generateWindowedCertificate(t, generateTestKey(t), caCert, caKey, tt.ek, true)

			err = store.VerifyCertificatesForAIK(&aikKey.PublicKey, aikDER, ekDER)
			if !errors.Is(err, tt.want) {
				t.Fatalf("VerifyCertificatesForAIK: want %v, got %v", tt.want, err)
			}
		})
	}
}

// helper to save certificate as PEM
func saveCertPEM(t *testing.T, path string, certDER []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Failed to create cert file: %v", err)
	}
	defer f.Close()

	f.WriteString("-----BEGIN CERTIFICATE-----\n")
	f.WriteString(base64Encode(certDER))
	f.WriteString("\n-----END CERTIFICATE-----\n")
}

// helper to generate expired certificate
func generateWindowedCertificate(t *testing.T, key *rsa.PrivateKey, ca *x509.Certificate, caKey *rsa.PrivateKey,
	window [2]time.Duration, ek bool,
) []byte {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"LOTA Test"},
			CommonName:   "Windowed Certificate",
		},
		NotBefore:             time.Now().Add(window[0]),
		NotAfter:              time.Now().Add(window[1]),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if ek {
		template.KeyUsage = x509.KeyUsageKeyEncipherment
		template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{2, 23, 133, 8, 1}}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create windowed certificate: %v", err)
	}

	return certDER
}

// simple base64 encoder for PEM
func base64Encode(data []byte) string {
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := make([]byte, 0, ((len(data)+2)/3)*4)

	for i := 0; i < len(data); i += 3 {
		var b uint32
		remaining := len(data) - i

		if remaining >= 3 {
			b = uint32(data[i])<<16 | uint32(data[i+1])<<8 | uint32(data[i+2])
			result = append(result, base64Chars[(b>>18)&0x3F], base64Chars[(b>>12)&0x3F],
				base64Chars[(b>>6)&0x3F], base64Chars[b&0x3F])
		} else if remaining == 2 {
			b = uint32(data[i])<<16 | uint32(data[i+1])<<8
			result = append(result, base64Chars[(b>>18)&0x3F], base64Chars[(b>>12)&0x3F],
				base64Chars[(b>>6)&0x3F], '=')
		} else {
			b = uint32(data[i]) << 16
			result = append(result, base64Chars[(b>>18)&0x3F], base64Chars[(b>>12)&0x3F], '=', '=')
		}
	}

	// add line breaks every 64 chars
	var formatted []byte
	for i := 0; i < len(result); i += 64 {
		end := i + 64
		if end > len(result) {
			end = len(result)
		}
		formatted = append(formatted, result[i:end]...)
		if end < len(result) {
			formatted = append(formatted, '\n')
		}
	}

	return string(formatted)
}

// issues an AIK leaf certificate with the given subject CN, signed by ca.
func issueAIKCert(t *testing.T, cn string, key *rsa.PrivateKey, ca *x509.Certificate, caKey *rsa.PrivateKey) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(77),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("issue AIK cert: %v", err)
	}
	return der
}

func TestCertificateVerifier_VerifyAIKCertificate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caKey := generateTestKey(t)
	caCert := generateTestCertificate(t, caKey, true)
	caCertPath := filepath.Join(tempDir, "ca.pem")
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	saveCertPEM(t, caCertPath, caCertDER)

	store, err := NewCertificateVerifier([]string{caCertPath}, nil)
	if err != nil {
		t.Fatalf("NewCertificateVerifier: %v", err)
	}

	aikKey := generateTestKey(t)
	const pseudonym = "device-pseudonym-abc123"
	aikDER := issueAIKCert(t, pseudonym, aikKey, caCert, caKey)

	cert, err := store.VerifyAIKCertificate(&aikKey.PublicKey, aikDER)
	if err != nil {
		t.Fatalf("VerifyAIKCertificate rejected a CA-issued cert: %v", err)
	}
	if cert.Subject.CommonName != pseudonym {
		t.Fatalf("subject CN %q, want %q", cert.Subject.CommonName, pseudonym)
	}

	otherKey := generateTestKey(t)
	if _, err := store.VerifyAIKCertificate(&otherKey.PublicKey, aikDER); !errors.Is(err, ErrCertificateKeyMatch) {
		t.Fatalf("AIK cert that does not certify the reported key: %v", err)
	}

	rogueCAKey := generateTestKey(t)
	rogueCA := generateTestCertificate(t, rogueCAKey, true)
	rogueDER := issueAIKCert(t, pseudonym, aikKey, rogueCA, rogueCAKey)
	if _, err := store.VerifyAIKCertificate(&aikKey.PublicKey, rogueDER); !errors.Is(err, ErrCertificateChain) {
		t.Fatalf("AIK cert from an untrusted CA: %v", err)
	}

	if _, err := store.VerifyAIKCertificate(&aikKey.PublicKey, nil); !errors.Is(err, ErrNoCertificate) {
		t.Fatalf("empty AIK certificate: %v", err)
	}
}

// generates an EK certificate signed by a CA with the TCG EK OID in EKU
func generateEKCertificate(t *testing.T, key *rsa.PrivateKey, ca *x509.Certificate, caKey *rsa.PrivateKey) []byte {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		Subject: pkix.Name{
			Organization: []string{"LOTA Test TPM Manufacturer"},
			CommonName:   "EK Certificate",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{{2, 23, 133, 8, 1}},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create EK certificate: %v", err)
	}

	return certDER
}

// generates an EK certificate WITHOUT the TCG OID (should be rejected)
func generateEKCertificateNoOID(t *testing.T, key *rsa.PrivateKey, ca *x509.Certificate, caKey *rsa.PrivateKey) []byte {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject: pkix.Name{
			Organization: []string{"LOTA Test"},
			CommonName:   "Fake EK Certificate",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create EK certificate without OID: %v", err)
	}

	return certDER
}

func TestCertificateVerifier_ValidEKCertificate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caKey := generateTestKey(t)
	caCert := generateTestCertificate(t, caKey, true)

	caCertPath := filepath.Join(tempDir, "ca.pem")
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	saveCertPEM(t, caCertPath, caCertDER)

	store, err := NewCertificateVerifier([]string{caCertPath}, nil)
	if err != nil {
		t.Fatalf("NewCertificateVerifier failed: %v", err)
	}

	aikKey := generateTestKey(t)
	aikCertDER := generateSignedCertificate(t, aikKey, caCert, caKey)

	ekKey := generateTestKey(t)
	ekCertDER := generateEKCertificate(t, ekKey, caCert, caKey)

	// should succeed: valid AIK cert + EK cert with TCG OID
	if err := store.VerifyCertificatesForAIK(&aikKey.PublicKey, aikCertDER, ekCertDER); err != nil {
		t.Errorf("Registration with valid EK cert should succeed: %v", err)
	}
}

func TestCertificateVerifier_EKCertificateMissingOID(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caKey := generateTestKey(t)
	caCert := generateTestCertificate(t, caKey, true)

	caCertPath := filepath.Join(tempDir, "ca.pem")
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	saveCertPEM(t, caCertPath, caCertDER)

	store, err := NewCertificateVerifier([]string{caCertPath}, nil)
	if err != nil {
		t.Fatalf("NewCertificateVerifier failed: %v", err)
	}

	aikKey := generateTestKey(t)
	aikCertDER := generateSignedCertificate(t, aikKey, caCert, caKey)

	ekKey := generateTestKey(t)
	ekCertDER := generateEKCertificateNoOID(t, ekKey, caCert, caKey)

	// should fail: EK cert without TCG OID
	err = store.VerifyCertificatesForAIK(&aikKey.PublicKey, aikCertDER, ekCertDER)
	if err == nil {
		t.Fatal("Registration with EK cert missing TCG OID should fail")
	}
	if !errors.Is(err, ErrCertificateEKOID) {
		t.Errorf("Expected ErrCertificateEKOID, got: %v", err)
	}
}

// generates an EK certificate carrying the TCG OID as a certificate
// policy, which is where genuine manufacturer EK certificates place it.
func generateEKCertificatePolicyOID(t *testing.T, key *rsa.PrivateKey, ca *x509.Certificate, caKey *rsa.PrivateKey) []byte {
	t.Helper()

	oid, err := x509.OIDFromInts([]uint64{2, 23, 133, 8, 1})
	if err != nil {
		t.Fatalf("EK policy OID: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(12),
		Subject: pkix.Name{
			Organization: []string{"LOTA Test TPM Manufacturer"},
			CommonName:   "EK Certificate (policy OID)",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		Policies:              []x509.OID{oid},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create EK certificate with policy OID: %v", err)
	}
	return certDER
}

// A manufacturer EK certificate that carries the TCG OID in a certificate
// policy (rather than an extended key usage) must be accepted. Checking
// only the EKU rejects real hardware.
func TestCertificateVerifier_EKCertificatePolicyOID(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	caKey := generateTestKey(t)
	caCert := generateTestCertificate(t, caKey, true)

	caCertPath := filepath.Join(tempDir, "ca.pem")
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	saveCertPEM(t, caCertPath, caCertDER)

	store, err := NewCertificateVerifier([]string{caCertPath}, nil)
	if err != nil {
		t.Fatalf("NewCertificateVerifier failed: %v", err)
	}

	aikKey := generateTestKey(t)
	aikCertDER := generateSignedCertificate(t, aikKey, caCert, caKey)

	ekKey := generateTestKey(t)
	ekCertDER := generateEKCertificatePolicyOID(t, ekKey, caCert, caKey)

	if err := store.VerifyCertificatesForAIK(&aikKey.PublicKey, aikCertDER, ekCertDER); err != nil {
		t.Errorf("EK cert with TCG OID in a certificate policy should be accepted: %v", err)
	}
}
