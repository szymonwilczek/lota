// SPDX-License-Identifier: MIT
// LOTA Verifier - Policy Ed25519 signature verification tests
//
// Tests Go-native signing/verification and cross-language
// interop with C-generated Ed25519 signatures.
//
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// generates an Ed25519 keypair and writes PEM files
func writeKeyPair(t *testing.T, dir string) (privPath, pubPath string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// private key -> PKCS#8 PEM
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	privPath = filepath.Join(dir, "test.key")
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	// public key -> SPKI PEM
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPath = filepath.Join(dir, "test.pub")
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(pubPath, pubPEM, 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	return privPath, pubPath
}

// signs data with the private key at privPath
func signData(t *testing.T, data []byte, privPath string) []byte {
	t.Helper()

	privPEM, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}

	block, _ := pem.Decode(privPEM)
	if block == nil {
		t.Fatal("no PEM block in private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("not an Ed25519 private key")
	}

	return ed25519.Sign(edKey, data)
}

func TestLoadPolicyPublicKey(t *testing.T) {
	dir := t.TempDir()
	_, pubPath := writeKeyPair(t, dir)

	pub, err := LoadPolicyPublicKey(pubPath)
	if err != nil {
		t.Fatalf("LoadPolicyPublicKey: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("pubkey length = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
}

func TestLoadPolicyPublicKey_NotFound(t *testing.T) {
	_, err := LoadPolicyPublicKey("/nonexistent/path.pub")
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestLoadPolicyPublicKey_BadPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pub")
	os.WriteFile(path, []byte("not a pem file"), 0o644)

	_, err := LoadPolicyPublicKey(path)
	if err == nil {
		t.Fatal("expected error for bad PEM")
	}
}

func TestVerifyPolicySignature_Valid(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath := writeKeyPair(t, dir)

	data := []byte("name: test-policy\npcrs:\n  0: abc123\n")
	sig := signData(t, data, privPath)

	pub, err := LoadPolicyPublicKey(pubPath)
	if err != nil {
		t.Fatalf("load pubkey: %v", err)
	}

	if err := VerifyPolicySignature(data, sig, pub); err != nil {
		t.Fatalf("expected valid signature, got: %v", err)
	}
}

func TestVerifyPolicySignature_Tampered(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath := writeKeyPair(t, dir)

	data := []byte("name: test-policy\npcrs:\n  0: abc123\n")
	sig := signData(t, data, privPath)

	// tamper
	data[0] = 'X'

	pub, err := LoadPolicyPublicKey(pubPath)
	if err != nil {
		t.Fatalf("load pubkey: %v", err)
	}

	err = VerifyPolicySignature(data, sig, pub)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
}

func TestVerifyPolicySignature_WrongKey(t *testing.T) {
	dir := t.TempDir()
	privPath1, _ := writeKeyPair(t, dir)

	// generate second keypair
	dir2 := t.TempDir()
	_, pubPath2 := writeKeyPair(t, dir2)

	data := []byte("signed with key1")
	sig := signData(t, data, privPath1)

	pub2, err := LoadPolicyPublicKey(pubPath2)
	if err != nil {
		t.Fatalf("load pubkey2: %v", err)
	}

	err = VerifyPolicySignature(data, sig, pub2)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
}

func TestVerifyPolicySignature_BadSigSize(t *testing.T) {
	dir := t.TempDir()
	_, pubPath := writeKeyPair(t, dir)

	pub, _ := LoadPolicyPublicKey(pubPath)

	err := VerifyPolicySignature([]byte("data"), []byte("short"), pub)
	if err != ErrBadSigSize {
		t.Fatalf("expected ErrBadSigSize, got: %v", err)
	}
}

func TestVerifyPolicySignature_EmptyMessage(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath := writeKeyPair(t, dir)

	data := []byte{}
	sig := signData(t, data, privPath)

	pub, _ := LoadPolicyPublicKey(pubPath)
	if err := VerifyPolicySignature(data, sig, pub); err != nil {
		t.Fatalf("expected valid sig on empty msg, got: %v", err)
	}
}

const signedPolicyYAML = "name: signed-test\npcrs:\n  0: \"" +
	"b6d107af0ef8a52065f6d3c344cfc811920fa81b28dd4c746ea1ad55464c5b61\"\n"

// writes the policy and, when sig is non-nil, its detached signature
func writeSignedPolicy(t *testing.T, dir string, content, sig []byte) string {
	t.Helper()

	yamlPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(yamlPath, content, 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if sig != nil {
		err := os.WriteFile(yamlPath+".sig", sig, 0o644)
		if err != nil {
			t.Fatalf("write signature: %v", err)
		}
	}
	return yamlPath
}

func signedPolicyVerifier(t *testing.T, pubPath string) *PCRVerifier {
	t.Helper()

	pub, err := LoadPolicyPublicKey(pubPath)
	if err != nil {
		t.Fatalf("load public key: %v", err)
	}
	v := NewPCRVerifier()
	v.SetPolicyPublicKey(pub)
	return v
}

func TestLoadPolicySigned_Valid(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath := writeKeyPair(t, dir)

	content := []byte(signedPolicyYAML)
	path := writeSignedPolicy(t, dir, content,
		signData(t, content, privPath))

	err := signedPolicyVerifier(t, pubPath).LoadPolicy(path)
	if err != nil {
		t.Fatalf("expected signed policy to load, got: %v", err)
	}
}

func TestLoadPolicySigned_Tampered(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath := writeKeyPair(t, dir)

	content := []byte(signedPolicyYAML)
	sig := signData(t, content, privPath)
	path := writeSignedPolicy(t, dir,
		[]byte(strings.Replace(signedPolicyYAML, "signed-test",
			"TAMPERED", 1)), sig)

	err := signedPolicyVerifier(t, pubPath).LoadPolicy(path)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got: %v", err)
	}
}

func TestLoadPolicySigned_MissingSig(t *testing.T) {
	dir := t.TempDir()
	_, pubPath := writeKeyPair(t, dir)

	path := writeSignedPolicy(t, dir, []byte(signedPolicyYAML), nil)

	err := signedPolicyVerifier(t, pubPath).LoadPolicy(path)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected missing signature error, got: %v", err)
	}
}

func TestLoadPolicySigned_TruncatedSig(t *testing.T) {
	dir := t.TempDir()
	_, pubPath := writeKeyPair(t, dir)

	path := writeSignedPolicy(t, dir, []byte(signedPolicyYAML),
		[]byte("short"))

	err := signedPolicyVerifier(t, pubPath).LoadPolicy(path)
	if !errors.Is(err, ErrBadSigSize) {
		t.Fatalf("expected ErrBadSigSize, got: %v", err)
	}
}

func TestLoadPolicy_TooLarge(t *testing.T) {
	dir := t.TempDir()

	content := []byte(signedPolicyYAML + "#" +
		strings.Repeat("x", PolicyMaxFileSize) + "\n")
	path := writeSignedPolicy(t, dir, content, nil)

	err := NewPCRVerifier().LoadPolicy(path)
	if !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("expected ErrFileTooLarge, got: %v", err)
	}
}
