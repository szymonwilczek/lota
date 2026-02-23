// SPDX-License-Identifier: MIT
// LOTA Verifier - AIK store tests

package store

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// creates a test RSA key pair
func generateTestKey(t *testing.T) *rsa.PrivateKey {
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

func TestMemoryStore_RegisterAndGet(t *testing.T) {
	store := NewMemoryStore()
	key := generateTestKey(t)

	// should not exist initially
	_, err := store.GetAIK("client1")
	if err == nil {
		t.Error("Expected error for non-existent client")
	}

	// register
	if err := store.RegisterAIK("client1", &key.PublicKey); err != nil {
		t.Fatalf("RegisterAIK failed: %v", err)
	}

	// should exist now
	gotKey, err := store.GetAIK("client1")
	if err != nil {
		t.Fatalf("GetAIK failed: %v", err)
	}

	if !publicKeysEqual(gotKey, &key.PublicKey) {
		t.Error("Retrieved key does not match registered key")
	}
}

func TestMemoryStore_RegisterDuplicateSameKey(t *testing.T) {
	store := NewMemoryStore()
	key := generateTestKey(t)

	if err := store.RegisterAIK("client1", &key.PublicKey); err != nil {
		t.Fatalf("First RegisterAIK failed: %v", err)
	}

	// registering same key should succeed (no-op)
	if err := store.RegisterAIK("client1", &key.PublicKey); err != nil {
		t.Errorf("Registering same key should succeed: %v", err)
	}
}

func TestMemoryStore_RegisterDuplicateDifferentKey(t *testing.T) {
	store := NewMemoryStore()
	key1 := generateTestKey(t)
	key2 := generateTestKey(t)

	if err := store.RegisterAIK("client1", &key1.PublicKey); err != nil {
		t.Fatalf("First RegisterAIK failed: %v", err)
	}

	// registering different key should fail
	if err := store.RegisterAIK("client1", &key2.PublicKey); err == nil {
		t.Error("Registering different key should fail")
	}
}

func TestMemoryStore_GlobalAIKUniquenessAcrossClients(t *testing.T) {
	store := NewMemoryStore()
	key := generateTestKey(t)

	if err := store.RegisterAIK("client1", &key.PublicKey); err != nil {
		t.Fatalf("First RegisterAIK failed: %v", err)
	}

	err := store.RegisterAIK("client2", &key.PublicKey)
	if !errors.Is(err, ErrAIKAlreadyRegistered) {
		t.Fatalf("Expected ErrAIKAlreadyRegistered, got: %v", err)
	}
}

func TestMemoryStore_ListClients(t *testing.T) {
	store := NewMemoryStore()
	key1 := generateTestKey(t)
	key2 := generateTestKey(t)

	store.RegisterAIK("client1", &key1.PublicKey)
	store.RegisterAIK("client2", &key2.PublicKey)

	clients := store.ListClients()
	if len(clients) != 2 {
		t.Errorf("Expected 2 clients, got %d", len(clients))
	}
}

func TestFileStore_RegisterAndGet(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store, err := NewFileStore(tempDir)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	key := generateTestKey(t)

	if err := store.RegisterAIK("client1", &key.PublicKey); err != nil {
		t.Fatalf("RegisterAIK failed: %v", err)
	}

	// verify file was created
	pemPath := filepath.Join(tempDir, "client1.pem")
	if _, err := os.Stat(pemPath); os.IsNotExist(err) {
		t.Error("PEM file was not created")
	}

	gotKey, err := store.GetAIK("client1")
	if err != nil {
		t.Fatalf("GetAIK failed: %v", err)
	}

	if !publicKeysEqual(gotKey, &key.PublicKey) {
		t.Error("Retrieved key does not match registered key")
	}
}

func TestFileStore_Persistence(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	key := generateTestKey(t)

	// create store and register key
	store1, err := NewFileStore(tempDir)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	if err := store1.RegisterAIK("client1", &key.PublicKey); err != nil {
		t.Fatalf("RegisterAIK failed: %v", err)
	}

	// create new store instance (simulates restart)
	store2, err := NewFileStore(tempDir)
	if err != nil {
		t.Fatalf("NewFileStore (second) failed: %v", err)
	}

	// key should still be there
	gotKey, err := store2.GetAIK("client1")
	if err != nil {
		t.Fatalf("GetAIK after 'restart' failed: %v", err)
	}

	if !publicKeysEqual(gotKey, &key.PublicKey) {
		t.Error("Key not persisted correctly")
	}
}

func TestFileStore_GlobalAIKUniquenessAcrossClients(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store, err := NewFileStore(tempDir)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	key := generateTestKey(t)

	if err := store.RegisterAIK("client1", &key.PublicKey); err != nil {
		t.Fatalf("First RegisterAIK failed: %v", err)
	}

	err = store.RegisterAIK("client2", &key.PublicKey)
	if !errors.Is(err, ErrAIKAlreadyRegistered) {
		t.Fatalf("Expected ErrAIKAlreadyRegistered, got: %v", err)
	}
}

func TestCertificateStore_TOFUMode(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// create store without requiring certs (TOFU mode)
	store, err := NewCertificateStore(tempDir, nil, false)
	if err != nil {
		t.Fatalf("NewCertificateStore failed: %v", err)
	}

	key := generateTestKey(t)

	// should work without certificates
	if err := store.RegisterAIK("client1", &key.PublicKey); err != nil {
		t.Errorf("TOFU registration should succeed: %v", err)
	}
}

func TestCertificateStore_RequireCerts(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// create store requiring certs
	store, err := NewCertificateStore(tempDir, nil, true)
	if err != nil {
		t.Fatalf("NewCertificateStore failed: %v", err)
	}

	key := generateTestKey(t)

	// should fail without certificates
	if err := store.RegisterAIK("client1", &key.PublicKey); err == nil {
		t.Error("Registration without cert should fail when certs required")
	}
}

func TestCertificateStore_ValidCertificate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// create CA
	caKey := generateTestKey(t)
	caCert := generateTestCertificate(t, caKey, true)

	// save CA cert
	caCertPath := filepath.Join(tempDir, "ca.pem")
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	saveCertPEM(t, caCertPath, caCertDER)

	// create store with CA
	store, err := NewCertificateStore(tempDir, []string{caCertPath}, false)
	if err != nil {
		t.Fatalf("NewCertificateStore failed: %v", err)
	}

	// create AIK key and certificate signed by CA
	aikKey := generateTestKey(t)
	aikCertDER := generateSignedCertificate(t, aikKey, caCert, caKey)

	// should succeed with valid certificate
	if err := store.RegisterAIKWithCert("client1", &aikKey.PublicKey, aikCertDER, nil); err != nil {
		t.Errorf("Registration with valid cert should succeed: %v", err)
	}
}

func TestCertificateStore_InvalidCertificateChain(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// create CA
	caKey := generateTestKey(t)
	caCert := generateTestCertificate(t, caKey, true)

	// save CA cert
	caCertPath := filepath.Join(tempDir, "ca.pem")
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	saveCertPEM(t, caCertPath, caCertDER)

	// create store with CA
	store, err := NewCertificateStore(tempDir, []string{caCertPath}, false)
	if err != nil {
		t.Fatalf("NewCertificateStore failed: %v", err)
	}

	// create self-signed cert (not signed by trusted CA)
	aikKey := generateTestKey(t)
	selfSignedCert := generateTestCertificate(t, aikKey, false)
	selfSignedDER, _ := x509.CreateCertificate(rand.Reader, selfSignedCert, selfSignedCert, &aikKey.PublicKey, aikKey)

	// should fail with untrusted certificate
	if err := store.RegisterAIKWithCert("client1", &aikKey.PublicKey, selfSignedDER, nil); err == nil {
		t.Error("Registration with untrusted cert should fail")
	}
}

func TestCertificateStore_KeyMismatch(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// create CA
	caKey := generateTestKey(t)
	caCert := generateTestCertificate(t, caKey, true)

	// save CA cert
	caCertPath := filepath.Join(tempDir, "ca.pem")
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	saveCertPEM(t, caCertPath, caCertDER)

	// create store with CA
	store, err := NewCertificateStore(tempDir, []string{caCertPath}, false)
	if err != nil {
		t.Fatalf("NewCertificateStore failed: %v", err)
	}

	// create AIK certificate
	aikKey := generateTestKey(t)
	aikCertDER := generateSignedCertificate(t, aikKey, caCert, caKey)

	// try to register with DIFFERENT public key
	differentKey := generateTestKey(t)
	if err := store.RegisterAIKWithCert("client1", &differentKey.PublicKey, aikCertDER, nil); err == nil {
		t.Error("Registration with mismatched key should fail")
	}
}

func TestCertificateStore_ExpiredCertificate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// create CA
	caKey := generateTestKey(t)
	caCert := generateTestCertificate(t, caKey, true)

	// save CA cert
	caCertPath := filepath.Join(tempDir, "ca.pem")
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	saveCertPEM(t, caCertPath, caCertDER)

	// create store with CA
	store, err := NewCertificateStore(tempDir, []string{caCertPath}, false)
	if err != nil {
		t.Fatalf("NewCertificateStore failed: %v", err)
	}

	// create expired certificate
	aikKey := generateTestKey(t)
	expiredCertDER := generateExpiredCertificate(t, aikKey, caCert, caKey)

	// should fail with expired certificate
	if err := store.RegisterAIKWithCert("client1", &aikKey.PublicKey, expiredCertDER, nil); err == nil {
		t.Error("Registration with expired cert should fail")
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
func generateExpiredCertificate(t *testing.T, key *rsa.PrivateKey, ca *x509.Certificate, caKey *rsa.PrivateKey) []byte {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"LOTA Test"},
			CommonName:   "Expired Certificate",
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // expired!
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create expired certificate: %v", err)
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

func TestFingerprint(t *testing.T) {
	key := generateTestKey(t)
	fp := Fingerprint(&key.PublicKey)

	// fingerprint should be hex-encoded SHA-256 (64 chars)
	if len(fp) != 64 {
		t.Errorf("Fingerprint should be 64 chars, got %d", len(fp))
	}

	// same key should produce same fingerprint
	fp2 := Fingerprint(&key.PublicKey)
	if fp != fp2 {
		t.Error("Same key should produce same fingerprint")
	}

	// different key should produce different fingerprint
	key2 := generateTestKey(t)
	fp3 := Fingerprint(&key2.PublicKey)
	if fp == fp3 {
		t.Error("Different keys should produce different fingerprints")
	}
}

func TestMemoryStore_GetRegisteredAt(t *testing.T) {
	store := NewMemoryStore()
	key := generateTestKey(t)

	// should fail for unknown client
	_, err := store.GetRegisteredAt("unknown")
	if err == nil {
		t.Error("Expected error for non-existent client")
	}

	before := time.Now()
	store.RegisterAIK("client1", &key.PublicKey)
	after := time.Now()

	regTime, err := store.GetRegisteredAt("client1")
	if err != nil {
		t.Fatalf("GetRegisteredAt failed: %v", err)
	}

	if regTime.Before(before) || regTime.After(after) {
		t.Errorf("Registration time %v not in expected range [%v, %v]", regTime, before, after)
	}
}

func TestMemoryStore_RotateAIK(t *testing.T) {
	store := NewMemoryStore()
	key1 := generateTestKey(t)
	key2 := generateTestKey(t)

	store.RegisterAIK("client1", &key1.PublicKey)

	// different key should fail via RegisterAIK (TOFU invariant)
	if err := store.RegisterAIK("client1", &key2.PublicKey); err == nil {
		t.Error("RegisterAIK should reject different key")
	}

	// rotation should succeed
	if err := store.RotateAIK("client1", &key2.PublicKey); err != nil {
		t.Fatalf("RotateAIK failed: %v", err)
	}

	// should now return new key
	gotKey, err := store.GetAIK("client1")
	if err != nil {
		t.Fatalf("GetAIK failed: %v", err)
	}
	if !publicKeysEqual(gotKey, &key2.PublicKey) {
		t.Error("Rotated key does not match expected key")
	}
}

func TestMemoryStore_RotatePreservesHardwareID(t *testing.T) {
	store := NewMemoryStore()
	key1 := generateTestKey(t)
	key2 := generateTestKey(t)
	hwid := [32]byte{0xCA, 0xFE, 0xBA, 0xBE}

	store.RegisterAIK("client1", &key1.PublicKey)
	store.RegisterHardwareID("client1", hwid)

	// rotate key
	store.RotateAIK("client1", &key2.PublicKey)

	// hardware ID should still be there
	gotHWID, err := store.GetHardwareID("client1")
	if err != nil {
		t.Fatalf("GetHardwareID after rotation failed: %v", err)
	}
	if gotHWID != hwid {
		t.Error("Hardware ID lost after AIK rotation")
	}
}

func TestMemoryStore_RotateUpdatesTimestamp(t *testing.T) {
	store := NewMemoryStore()
	key1 := generateTestKey(t)
	key2 := generateTestKey(t)

	store.RegisterAIK("client1", &key1.PublicKey)
	regTime1, _ := store.GetRegisteredAt("client1")

	// small sleep to ensure different timestamp
	time.Sleep(10 * time.Millisecond)

	store.RotateAIK("client1", &key2.PublicKey)
	regTime2, _ := store.GetRegisteredAt("client1")

	if !regTime2.After(regTime1) {
		t.Errorf("Rotation should update timestamp: before=%v, after=%v", regTime1, regTime2)
	}
}

func TestMemoryStore_RotateNonexistent(t *testing.T) {
	store := NewMemoryStore()
	key := generateTestKey(t)

	if err := store.RotateAIK("nonexistent", &key.PublicKey); err == nil {
		t.Error("RotateAIK should fail for non-existent client")
	}
}

func TestFileStore_GetRegisteredAt(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store, err := NewFileStore(tempDir)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	key := generateTestKey(t)

	before := time.Now()
	store.RegisterAIK("client1", &key.PublicKey)
	after := time.Now()

	regTime, err := store.GetRegisteredAt("client1")
	if err != nil {
		t.Fatalf("GetRegisteredAt failed: %v", err)
	}

	if regTime.Before(before) || regTime.After(after) {
		t.Errorf("Registration time %v not in expected range [%v, %v]", regTime, before, after)
	}

	// verify .meta file was created
	metaPath := filepath.Join(tempDir, "client1.meta")
	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		t.Error("Metadata file was not created")
	}
}

func TestFileStore_RotateAIK(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store, err := NewFileStore(tempDir)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	key1 := generateTestKey(t)
	key2 := generateTestKey(t)

	store.RegisterAIK("client1", &key1.PublicKey)

	// rotate
	if err := store.RotateAIK("client1", &key2.PublicKey); err != nil {
		t.Fatalf("RotateAIK failed: %v", err)
	}

	// verify new key is returned
	gotKey, err := store.GetAIK("client1")
	if err != nil {
		t.Fatalf("GetAIK failed: %v", err)
	}
	if !publicKeysEqual(gotKey, &key2.PublicKey) {
		t.Error("Rotated key does not match")
	}

	// verify persistence: reload store
	store2, err := NewFileStore(tempDir)
	if err != nil {
		t.Fatalf("NewFileStore (reload) failed: %v", err)
	}

	gotKey2, err := store2.GetAIK("client1")
	if err != nil {
		t.Fatalf("GetAIK after reload failed: %v", err)
	}
	if !publicKeysEqual(gotKey2, &key2.PublicKey) {
		t.Error("Rotated key not persisted correctly")
	}
}

func TestFileStore_RotatePreservesHardwareID(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store, err := NewFileStore(tempDir)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	key1 := generateTestKey(t)
	key2 := generateTestKey(t)
	hwid := [32]byte{0xDE, 0xAD, 0xBE, 0xEF}

	store.RegisterAIK("client1", &key1.PublicKey)
	store.RegisterHardwareID("client1", hwid)

	store.RotateAIK("client1", &key2.PublicKey)

	gotHWID, err := store.GetHardwareID("client1")
	if err != nil {
		t.Fatalf("GetHardwareID after rotation failed: %v", err)
	}
	if gotHWID != hwid {
		t.Error("Hardware ID lost after AIK rotation")
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

func TestCertificateStore_ValidEKCertificate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	storePath := filepath.Join(tempDir, "store")
	if err := os.Mkdir(storePath, 0700); err != nil {
		t.Fatalf("Failed to create store dir: %v", err)
	}

	caKey := generateTestKey(t)
	caCert := generateTestCertificate(t, caKey, true)

	caCertPath := filepath.Join(tempDir, "ca.pem")
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	saveCertPEM(t, caCertPath, caCertDER)

	store, err := NewCertificateStore(storePath, []string{caCertPath}, false)
	if err != nil {
		t.Fatalf("NewCertificateStore failed: %v", err)
	}

	aikKey := generateTestKey(t)
	aikCertDER := generateSignedCertificate(t, aikKey, caCert, caKey)

	ekKey := generateTestKey(t)
	ekCertDER := generateEKCertificate(t, ekKey, caCert, caKey)

	// should succeed: valid AIK cert + EK cert with TCG OID
	if err := store.RegisterAIKWithCert("client-ek", &aikKey.PublicKey, aikCertDER, ekCertDER); err != nil {
		t.Errorf("Registration with valid EK cert should succeed: %v", err)
	}
}

func TestCertificateStore_EKCertificateMissingOID(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	storePath := filepath.Join(tempDir, "store")
	if err := os.Mkdir(storePath, 0700); err != nil {
		t.Fatalf("Failed to create store dir: %v", err)
	}

	caKey := generateTestKey(t)
	caCert := generateTestCertificate(t, caKey, true)

	caCertPath := filepath.Join(tempDir, "ca.pem")
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	saveCertPEM(t, caCertPath, caCertDER)

	store, err := NewCertificateStore(storePath, []string{caCertPath}, false)
	if err != nil {
		t.Fatalf("NewCertificateStore failed: %v", err)
	}

	aikKey := generateTestKey(t)
	aikCertDER := generateSignedCertificate(t, aikKey, caCert, caKey)

	ekKey := generateTestKey(t)
	ekCertDER := generateEKCertificateNoOID(t, ekKey, caCert, caKey)

	// should fail: EK cert without TCG OID
	err = store.RegisterAIKWithCert("client-ek-bad", &aikKey.PublicKey, aikCertDER, ekCertDER)
	if err == nil {
		t.Fatal("Registration with EK cert missing TCG OID should fail")
	}
	if !errors.Is(err, ErrCertificateEKOID) {
		t.Errorf("Expected ErrCertificateEKOID, got: %v", err)
	}
}

func TestFileStore_PathTraversal(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "lota-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	store, err := NewFileStore(tempDir)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	key := generateTestKey(t)
	hwid := [32]byte{0xDE, 0xAD}

	malicious := []string{
		"../etc/shadow",
		"../../etc/passwd",
		"foo/bar",
		"foo\\bar",
		"clean\x00evil",
		"..",
		"",
	}

	for _, id := range malicious {
		label := fmt.Sprintf("%q", id)

		if err := store.RegisterAIK(id, &key.PublicKey); !errors.Is(err, ErrInvalidClientID) {
			t.Errorf("RegisterAIK(%s): want ErrInvalidClientID, got %v", label, err)
		}

		if _, err := store.GetAIK(id); !errors.Is(err, ErrInvalidClientID) {
			t.Errorf("GetAIK(%s): want ErrInvalidClientID, got %v", label, err)
		}

		if _, err := store.GetRegisteredAt(id); !errors.Is(err, ErrInvalidClientID) {
			t.Errorf("GetRegisteredAt(%s): want ErrInvalidClientID, got %v", label, err)
		}

		if err := store.RotateAIK(id, &key.PublicKey); !errors.Is(err, ErrInvalidClientID) {
			t.Errorf("RotateAIK(%s): want ErrInvalidClientID, got %v", label, err)
		}

		if err := store.RegisterHardwareID(id, hwid); !errors.Is(err, ErrInvalidClientID) {
			t.Errorf("RegisterHardwareID(%s): want ErrInvalidClientID, got %v", label, err)
		}

		if _, err := store.GetHardwareID(id); !errors.Is(err, ErrInvalidClientID) {
			t.Errorf("GetHardwareID(%s): want ErrInvalidClientID, got %v", label, err)
		}
	}
}
