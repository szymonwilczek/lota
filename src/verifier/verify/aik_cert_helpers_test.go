// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// Shared test fixtures for the Privacy CA attestation model: a test
// attestation CA that issues AIK certificates whose subject carries the
// device pseudonym, and a certificate-verifying AIK store that trusts it.

package verify

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/store"
)

var (
	testCAKey  *rsa.PrivateKey
	testCACert *x509.Certificate
)

func init() {
	var err error
	testCAKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("test CA key: " + err.Error())
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "lota-test-attest-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &testCAKey.PublicKey, testCAKey)
	if err != nil {
		panic("test CA cert: " + err.Error())
	}
	testCACert, err = x509.ParseCertificate(der)
	if err != nil {
		panic("parse test CA cert: " + err.Error())
	}
}

// testPseudonym maps an arbitrary client label to a deterministic 64-hex
// device pseudonym, matching the shape the attestation CA issues.
func testPseudonym(clientID string) string {
	h := sha256.Sum256([]byte("lota-test-pseudonym:" + clientID))
	return hex.EncodeToString(h[:])
}

// testAIKCertOUs, when non-nil, becomes the Subject.OrganizationalUnit of every
// certificate issueAIKCertOrPanic mints.
// Tenant tests set it around report creation and reset it afterwards.
var testAIKCertOUs []string

// issueAIKCertOrPanic mints an AIK certificate with the given pseudonym
// subject, certifying aikPub and signed by the test CA.
func issueAIKCertOrPanic(pseudonym string, aikPub *rsa.PublicKey) []byte {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: pseudonym, OrganizationalUnit: testAIKCertOUs},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, testCACert, aikPub, testCAKey)
	if err != nil {
		panic("issue test AIK cert: " + err.Error())
	}
	return der
}

// newCertStore returns a certificate-verifying AIK store that trusts the
// test attestation CA, the production-shaped trust anchor.
func newCertStore(t *testing.T) store.AIKStore {
	t.Helper()
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCACert.Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write test CA: %v", err)
	}
	cs, err := store.NewCertificateStore(filepath.Join(dir, "store"), []string{caPath}, true)
	if err != nil {
		t.Fatalf("NewCertificateStore: %v", err)
	}
	return cs
}
