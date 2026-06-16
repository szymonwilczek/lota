// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// Benchmarks for the credential-activation primitives. GenerateChallenge is
// the per-enrollment RSA MakeCredential cost that the server-side Begin rate
// limit (T-MED-1) is designed to bound; ValidateAIK is the template parse on
// the same path.

package credential

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/szymonwilczek/lota/attestca/internal/tpmtest"
)

func BenchmarkGenerateChallenge(b *testing.B) {
	ekKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	_, aikName := tpmtest.AIKTemplate(b)

	b.ReportAllocs()
	for b.Loop() {
		ch, err := GenerateChallenge(&ekKey.PublicKey, aikName)
		if err != nil {
			b.Fatal(err)
		}
		_ = ch
	}
}

func BenchmarkValidateAIK(b *testing.B) {
	aikTPMT, _ := tpmtest.AIKTemplate(b)

	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := ValidateAIK(aikTPMT); err != nil {
			b.Fatal(err)
		}
	}
}
