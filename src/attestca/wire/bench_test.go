// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// Benchmarks for the enrollment wire codec (pure CPU, no TPM).

package wire

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func benchBegin() *BeginRequest {
	return &BeginRequest{
		EKCertDER: randBytes(2048), // typical DER EK certificate
		AIKPublic: randBytes(312),  // marshaled TPMT_PUBLIC (RSA-2048)
	}
}

func benchResult() *ResultReply {
	return &ResultReply{
		Status:     StatusOK,
		AIKCertDER: randBytes(640), // issued AIK certificate
		DeviceID:   hex.EncodeToString(randBytes(32)),
	}
}

func BenchmarkEncodeBegin(b *testing.B) {
	req := benchBegin()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := EncodeBegin(req); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeBegin(b *testing.B) {
	body, err := EncodeBegin(benchBegin())
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DecodeBegin(body); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeResult(b *testing.B) {
	r := benchResult()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := EncodeResult(r); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeResult(b *testing.B) {
	body, err := EncodeResult(benchResult())
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DecodeResult(body); err != nil {
			b.Fatal(err)
		}
	}
}
