// SPDX-License-Identifier: MIT
// LOTA Verifier - Policy Ed25519 signature verification
//
// Verifies that YAML policy files have not been tampered with.
// Signatures are detached: policy.yaml + policy.yaml.sig
//
// Compatible with signatures produced by the C agent:
//   lota-agent --sign-policy policy.yaml --signing-key key.key
//
// Key format: PEM-encoded SubjectPublicKeyInfo (SPKI) with Ed25519.
// Signature format: raw 64-byte Ed25519 signature.
//
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Ed25519 signature size in bytes
const PolicySigSize = 64

// Maximum policy file size (64 KiB)
const PolicyMaxFileSize = 64 * 1024

var (
	// returned when Ed25519 verification fails
	ErrInvalidSignature = errors.New("invalid Ed25519 signature")

	// returned when the PEM public key is not Ed25519 SPKI
	ErrBadKeyFormat = errors.New("not an Ed25519 public key")

	// returned when a file exceeds PolicyMaxFileSize
	ErrFileTooLarge = errors.New("file exceeds maximum size")

	// returned when the signature file is not exactly 64 bytes
	ErrBadSigSize = errors.New("signature must be exactly 64 bytes")
)

// reads a PEM-encoded Ed25519 public key (SPKI format)
// returns the ed25519.PublicKey or an error if the file is malformed
func LoadPolicyPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, ErrBadKeyFormat
	}

	return edPub, nil
}

// checks an Ed25519 signature over raw policy data
// sig must be exactly 64 bytes!
// returns nil if valid, ErrInvalidSignature if not
func VerifyPolicySignature(data []byte, sig []byte, pubKey ed25519.PublicKey) error {
	if len(sig) != PolicySigSize {
		return ErrBadSigSize
	}

	if !ed25519.Verify(pubKey, data, sig) {
		return ErrInvalidSignature
	}

	return nil
}

// verifies the detached Ed25519 signature on a policy file
// reads policyPath and policyPath+".sig", then verifies with pubKey
//
// returns nil if signature is valid
func VerifyPolicyFile(policyPath string, pubKey ed25519.PublicKey) error {
	data, err := readBoundedFile(policyPath, PolicyMaxFileSize)
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}

	sigPath := policyPath + ".sig"
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("read signature file: %w", err)
	}

	return VerifyPolicySignature(data, sig, pubKey)
}

// reads a file up to maxSize bytes
// returns ErrFileTooLarge if the file exceeds the limit
func readBoundedFile(path string, maxSize int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.Size() > maxSize {
		return nil, ErrFileTooLarge
	}

	return os.ReadFile(path)
}
