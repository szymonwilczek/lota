// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// Benchmarks for the Go server-side token path:
// VerifyToken is the per-heartbeat cost game server pays
// (RSASSA signature verify + nonce binding check + parse);
// ParseToken is the untrusted parse alone.

package server

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

func benchToken(b *testing.B) ([]byte, *rsa.PrivateKey, [32]byte) {
	b.Helper()
	key := generateTestKey(b)
	var nonce [32]byte
	_, _ = rand.Read(nonce[:])
	validUntil := uint64(time.Now().Add(2 * time.Minute).Unix())
	pcrDigest := make([]byte, 32)
	_, _ = rand.Read(pcrDigest)
	tok := buildTestToken(b, key, validUntil, 0x07, nonce, 0x4001, pcrDigest)
	return tok, key, nonce
}

func BenchmarkVerifyToken(b *testing.B) {
	tok, key, nonce := benchToken(b)
	pub := &key.PublicKey
	b.SetBytes(int64(len(tok)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := VerifyToken(tok, pub, nonce[:]); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseToken(b *testing.B) {
	tok, _, _ := benchToken(b)
	b.SetBytes(int64(len(tok)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ParseToken(tok); err != nil {
			b.Fatal(err)
		}
	}
}
