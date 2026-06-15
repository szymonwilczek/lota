// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Attestation CA - ROCA fingerprint tests

package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"
)

// rocaWeakModulus returns 65537^128:
// every residue mod the fingerprint primes is a power of 65537 by construction,
// so the value is a guaranteed-positive test vector of RSA-2048 size (2049 bits)
// without needing a captured RSALib key.
func rocaWeakModulus() *big.Int {
	return new(big.Int).Exp(big.NewInt(65537), big.NewInt(128), nil)
}

func TestIsROCAWeak_PositiveVector(t *testing.T) {
	if !IsROCAWeak(rocaWeakModulus()) {
		t.Fatal("65537^128 must carry the ROCA fingerprint")
	}
	// generator itself is the minimal in-subgroup value everywhere
	if !IsROCAWeak(big.NewInt(65537)) {
		t.Fatal("65537 must carry the ROCA fingerprint")
	}
}

func TestIsROCAWeak_RandomKeyNegative(t *testing.T) {
	// Go-generated RSA modulus matches all 17 subgroup tests with
	// probability ~2^-154
	// hit here means the detector is broken
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	if IsROCAWeak(key.PublicKey.N) {
		t.Fatal("random RSA modulus flagged as ROCA-weak")
	}
}

func TestIsROCAWeak_DegenerateInputs(t *testing.T) {
	if IsROCAWeak(nil) {
		t.Fatal("nil modulus flagged")
	}
	if IsROCAWeak(big.NewInt(0)) {
		t.Fatal("zero modulus flagged")
	}
	if IsROCAWeak(new(big.Int).Neg(rocaWeakModulus())) {
		t.Fatal("negative modulus flagged")
	}
}

// TestVerifyEKCertificateRejectsROCAWeakEK drives the full gate:
// chain-valid, OID-carrying EK certificate whose RSA modulus carries
// the fingerprint must be refused with ErrEKWeakKey even though no CRL
// is configured.
func TestVerifyEKCertificateRejectsROCAWeakEK(t *testing.T) {
	root := makeRoot(t, "tpm-vendor-root")
	is := newTestIssuer(t, root)

	ekPolicyOID, err := x509.OIDFromInts([]uint64{2, 23, 133, 8, 1})
	if err != nil {
		t.Fatalf("EK policy OID: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: mustSerial(t),
		Subject:      pkix.Name{CommonName: "tpm-ek-roca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		Policies:     []x509.OID{ekPolicyOID},
	}
	weakPub := &rsa.PublicKey{N: rocaWeakModulus(), E: 65537}
	ekDER, err := x509.CreateCertificate(rand.Reader, tmpl, root.cert, weakPub, root.key)
	if err != nil {
		t.Fatalf("ROCA EK cert: %v", err)
	}

	_, err = is.VerifyEKCertificate(ekDER, time.Now())
	if !errors.Is(err, ErrEKWeakKey) {
		t.Fatalf("expected ErrEKWeakKey, got %v", err)
	}
}
