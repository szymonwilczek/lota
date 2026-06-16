// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// Package tpmtest provides hardware-free test fixtures for the
// attestation CA: a manufacturer root, EK certificates, AIK templates,
// the operator CA material, and a software model of
// TPM2_ActivateCredential. It lets the CA flow be exercised end to end
// without a TPM. It is test-support only and never imported by the
// shipped binaries.
package tpmtest

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
)

// Root is a self-signed manufacturer or CA root with its signing key.
type Root struct {
	Cert *x509.Certificate
	DER  []byte
	Key  crypto.Signer
}

// EK bundles a generated endorsement key with its certificate.
type EK struct {
	Priv    *rsa.PrivateKey
	CertDER []byte
}

func serial(tb testing.TB) *big.Int {
	tb.Helper()
	s, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		tb.Fatalf("serial: %v", err)
	}
	return s
}

// NewVendorRoot returns a self-signed ECDSA root.
func NewVendorRoot(tb testing.TB, cn string) Root {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("root key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(tb),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		tb.Fatalf("root cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatalf("parse root cert: %v", err)
	}
	return Root{Cert: cert, DER: der, Key: key}
}

// NewEKCert mints a valid RSA EK certificate under root, carrying the TCG
// EK OID as a certificate policy.
func NewEKCert(tb testing.TB, root Root) EK {
	tb.Helper()
	ekKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("EK key: %v", err)
	}
	oid, err := x509.OIDFromInts([]uint64{2, 23, 133, 8, 1})
	if err != nil {
		tb.Fatalf("EK OID: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(tb),
		Subject:      pkix.Name{CommonName: "tpm-ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		Policies:     []x509.OID{oid},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.Cert, &ekKey.PublicKey, root.Key)
	if err != nil {
		tb.Fatalf("EK cert: %v", err)
	}
	return EK{Priv: ekKey, CertDER: der}
}

// AIKTemplate returns a TPMT_PUBLIC for a restricted RSA signing key that
// matches the agent's create_aik_primary() template, along with its name.
func AIKTemplate(tb testing.TB) (tpmtPublic []byte, name tpm2.Name) {
	tb.Helper()
	mod := make([]byte, 256)
	if _, err := rand.Read(mod); err != nil {
		tb.Fatalf("modulus: %v", err)
	}
	mod[0] |= 0x80

	pub := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
			tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
			tpm2.FlagRestricted | tpm2.FlagSign,
		RSAParameters: &tpm2.RSAParams{
			Symmetric:  &tpm2.SymScheme{Alg: tpm2.AlgNull},
			Sign:       &tpm2.SigScheme{Alg: tpm2.AlgRSASSA, Hash: tpm2.AlgSHA256},
			KeyBits:    2048,
			ModulusRaw: mod,
		},
	}
	enc, err := pub.Encode()
	if err != nil {
		tb.Fatalf("encode AIK: %v", err)
	}
	n, err := pub.Name()
	if err != nil {
		tb.Fatalf("AIK name: %v", err)
	}
	return enc, n
}

// LOTACAPEM returns a self-signed ECDSA CA certificate and PKCS#8 key in
// PEM, suitable for ca.NewIssuer.
func LOTACAPEM(tb testing.TB) (caCertPEM, caKeyPEM []byte) {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(tb),
		Subject:               pkix.Name{CommonName: "lota-attest-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		tb.Fatalf("CA cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		tb.Fatalf("marshal CA key: %v", err)
	}
	return PEM("CERTIFICATE", der), PEM("PRIVATE KEY", keyDER)
}

// PEM wraps DER bytes in a PEM block.
func PEM(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

// SoftwareActivate models TPM2_ActivateCredential: decrypts the seed
// with the EK private key, re-derives the storage and integrity keys via
// KDFa, verifies the outer HMAC, and recovers the wrapped secret.
// It is the oracle that proves a CA-issued challenge is activatable without
// a TPM.
func SoftwareActivate(tb testing.TB, ekPriv *rsa.PrivateKey, aikName tpm2.Name,
	credBlob, encSecret []byte,
) []byte {
	tb.Helper()

	if len(encSecret) < 2 {
		tb.Fatalf("encSecret too short: %d", len(encSecret))
	}
	seedLen := int(binary.BigEndian.Uint16(encSecret[:2]))
	if 2+seedLen > len(encSecret) {
		tb.Fatalf("encSecret truncated")
	}
	seed, err := rsa.DecryptOAEP(sha256.New(), nil, ekPriv,
		encSecret[2:2+seedLen], append([]byte("IDENTITY"), 0))
	if err != nil {
		tb.Fatalf("OAEP decrypt: %v", err)
	}

	if len(credBlob) < 2 {
		tb.Fatalf("credBlob too short: %d", len(credBlob))
	}
	idLen := int(binary.BigEndian.Uint16(credBlob[:2]))
	if 2+idLen > len(credBlob) {
		tb.Fatalf("credBlob truncated")
	}
	id := credBlob[2 : 2+idLen]
	if len(id) < 2 {
		tb.Fatalf("IDObject too short")
	}
	macLen := int(binary.BigEndian.Uint16(id[:2]))
	if 2+macLen > len(id) {
		tb.Fatalf("IDObject HMAC truncated")
	}
	mac := id[2 : 2+macLen]
	encIdentity := id[2+macLen:]

	aikEnc, err := aikName.Digest.Encode()
	if err != nil {
		tb.Fatalf("encode AIK name: %v", err)
	}

	macKey, err := tpm2.KDFa(tpm2.AlgSHA256, seed, "INTEGRITY", nil, nil, sha256.Size*8)
	if err != nil {
		tb.Fatalf("KDFa integrity: %v", err)
	}
	m := hmac.New(sha256.New, macKey)
	m.Write(encIdentity)
	m.Write(aikEnc)
	if !hmac.Equal(m.Sum(nil), mac) {
		tb.Fatal("integrity HMAC mismatch")
	}

	symKey, err := tpm2.KDFa(tpm2.AlgSHA256, seed, "STORAGE", aikEnc, nil, 16*8)
	if err != nil {
		tb.Fatalf("KDFa storage: %v", err)
	}
	block, err := aes.NewCipher(symKey)
	if err != nil {
		tb.Fatalf("aes: %v", err)
	}
	cv := make([]byte, len(encIdentity))
	// CFB is mandated by TPM 2.0 credential protection
	// this oracle mirrors the TPM, it does not choose the cipher mode
	cipher.NewCFBDecrypter(block, make([]byte, 16)).XORKeyStream(cv, encIdentity) //nolint:staticcheck // CFB is mandated by TPM 2.0 credential protection

	if len(cv) < 2 {
		tb.Fatalf("decrypted credential too short")
	}
	secLen := int(binary.BigEndian.Uint16(cv[:2]))
	if 2+secLen > len(cv) {
		tb.Fatalf("decrypted secret truncated")
	}
	return cv[2 : 2+secLen]
}
