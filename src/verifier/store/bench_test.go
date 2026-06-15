// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// Benchmark for the verifier's per-attestation AIK lookup. The verifier
// resolves the client's registered AIK on every report it processes, so
// GetAIK throughput bounds steady-state attestations/sec on the store side.

package store

import "testing"

func BenchmarkSQLiteGetAIK(b *testing.B) {
	st, cleanup := createTestSQLiteAIKStore(b)
	defer cleanup()

	key := generateTestKey(b)
	if err := st.RegisterAIK("bench-client", &key.PublicKey); err != nil {
		b.Fatalf("RegisterAIK: %v", err)
	}

	b.ReportAllocs()
	for b.Loop() {
		if _, err := st.GetAIK("bench-client"); err != nil {
			b.Fatal(err)
		}
	}
}
