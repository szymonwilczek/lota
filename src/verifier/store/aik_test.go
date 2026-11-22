// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - AIK store tests

package store

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
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
	tests := []struct {
		name   string
		window [2]time.Duration
		want   error
	}{
		{"expired", [2]time.Duration{-48 * time.Hour, -24 * time.Hour}, ErrCertificateExpired},
		{"future", [2]time.Duration{24 * time.Hour, 48 * time.Hour}, ErrCertificateNotYet},
	}

	caKey := generateTestKey(t)
	caCert := generateTestCertificate(t, caKey, true)
	caCertDER, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	caCertPath := filepath.Join(t.TempDir(), "ca.pem")
	saveCertPEM(t, caCertPath, caCertDER)

	cv, err := NewCertificateVerifier([]string{caCertPath}, nil)
	if err != nil {
		t.Fatalf("NewCertificateVerifier failed: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aikKey := generateTestKey(t)
			aikDER := generateWindowedCertificate(t, aikKey, caCert, caKey, tt.window)

			if _, err := cv.VerifyAIKCertificate(&aikKey.PublicKey, aikDER); !errors.Is(err, tt.want) {
				t.Fatalf("VerifyAIKCertificate: want %v, got %v", tt.want, err)
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
	window [2]time.Duration,
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
