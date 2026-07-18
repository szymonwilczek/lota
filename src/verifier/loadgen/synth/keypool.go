// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Load Generator - AIK key pool persistence
//
// RSA key generation dominates rig setup time (tens of milliseconds per key),
// so rig directory persists the pool once and every later run reloads it.
// Certificates are cheap (one CA signature each) and are re-issued in memory at load time.

package synth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GenerateKeyPool builds n RSA-2048 AIK keys across all CPUs
func GenerateKeyPool(n int) ([]*rsa.PrivateKey, error) {
	if n <= 0 {
		return nil, fmt.Errorf("key pool size must be positive, got %d", n)
	}
	keys := make([]*rsa.PrivateKey, n)
	if err := parallelFor(n, func(i int) error {
		k, err := rsa.GenerateKey(rand.Reader, aikKeyBits)
		if err != nil {
			return fmt.Errorf("generate AIK key %d: %w", i, err)
		}
		keys[i] = k
		return nil
	}); err != nil {
		return nil, err
	}
	return keys, nil
}

// KeyPoolPEM serializes the pool as concatenated PKCS#8 PEM blocks
func KeyPoolPEM(keys []*rsa.PrivateKey) ([]byte, error) {
	var out []byte
	for i, k := range keys {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("marshal AIK key %d: %w", i, err)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: der,
		})...)
	}
	return out, nil
}

// LoadKeyPool parses KeyPoolPEM blob back into keys
func LoadKeyPool(data []byte) ([]*rsa.PrivateKey, error) {
	var keys []*rsa.PrivateKey
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse AIK key %d: %w", len(keys), err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("AIK key %d is not RSA", len(keys))
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys in pool")
	}
	return keys, nil
}
