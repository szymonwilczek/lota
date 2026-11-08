// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Policy Ed25519 signature verification

package verify

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// PolicySigSize is the size of a raw Ed25519 signature.
const PolicySigSize = 64

// PolicyMaxFileSize bounds the policy file VerifyPolicyFile reads.
const PolicyMaxFileSize = 64 * 1024

var (
	ErrInvalidSignature = errors.New("invalid Ed25519 signature")
	ErrBadKeyFormat     = errors.New("not an Ed25519 public key")
	ErrFileTooLarge     = errors.New("file exceeds maximum size")
	ErrBadSigSize       = errors.New("signature must be exactly 64 bytes")
)

// LoadPolicyPublicKey reads the PEM SubjectPublicKeyInfo Ed25519 key at path.
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

// VerifyPolicySignature verifies the raw Ed25519 signature sig over data.
func VerifyPolicySignature(data, sig []byte, pubKey ed25519.PublicKey) error {
	if len(sig) != PolicySigSize {
		return ErrBadSigSize
	}

	if !ed25519.Verify(pubKey, data, sig) {
		return ErrInvalidSignature
	}

	return nil
}

// VerifyPolicyFile verifies policyPath against the detached signature in
// policyPath+".sig", the form lota-agent --sign-policy writes.
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
