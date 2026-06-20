// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// FuzzVerifyReport drives the verifier's top-level entrypoint.
// Rather than mutate serialized bytes (which never survive the signature gate),
// it consumes fuzzer bytes into the policy-relevant report fields and RE-SIGNS
// self-consistent report, so mutation reaches the PCR-digest binding, nonce
// binding, event-log replay and kernel/agent/IOMMU policy gates.
//
// Oracle invariants, independent of the policy implementation:
//   - result is always returned (never nil-without-error),
//   - error and the result code agree (err==nil iff VerifyOK),
//   - acceptance yields session token with a future expiry,
//   - accept/reject decision is deterministic for a fixed spec
func FuzzVerifyReport(f *testing.F) {
	aikStore := newFuzzCertStore(f)
	cfg := DefaultConfig()
	cfg.RequireCert = false
	cfg.RequireBootPCRs = false
	cfg.RequireInitramfsLock = false
	cfg.NonceLifetime = time.Hour
	v := NewVerifier(cfg, aikStore)
	if err := v.AddPolicy(DefaultPolicy()); err != nil {
		f.Fatalf("AddPolicy: %v", err)
	}
	if err := v.SetActivePolicy("default"); err != nil {
		f.Fatalf("SetActivePolicy: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatalf("AIK key: %v", err)
	}

	// seed: the spec that reproduces a full through-path (VerifyOK)
	f.Add(encodeFuzzReportSpec(nominalSpec()))
	// seed: a wrong-nonce envelope (valid crypto, nonce gate must reject)
	wrongNonce := nominalSpec()
	wrongNonce.bindNonce = false
	f.Add(encodeFuzzReportSpec(wrongNonce))
	f.Add([]byte{})

	// verifyOnce builds and submits a fresh report for spec under a fresh
	// challenge, returning whether the verifier accepted it
	verifyOnce := func(t *testing.T, clientID string, spec *fuzzReportSpec) bool {
		ch, err := v.GenerateChallenge(clientID)
		if err != nil {
			t.Fatalf("GenerateChallenge: %v", err)
		}
		report := buildSignedReport(spec, clientID, ch.Nonce, key)
		result, err := v.VerifyReport(clientID, report)

		if result == nil {
			t.Fatalf("VerifyReport returned nil result (err=%v)", err)
		}
		accepted := err == nil
		if accepted != (result.Result == types.VerifyOK) {
			t.Fatalf("error/result disagree: err=%v result=%d", err, result.Result)
		}
		if accepted {
			if len(result.SessionToken) == 0 {
				t.Fatalf("accepted report produced no session token")
			}
			if result.ValidUntil <= uint64(time.Now().Unix()) {
				t.Fatalf("accepted report has non-future expiry %d", result.ValidUntil)
			}
		}
		return accepted
	}

	var clientSeq atomic.Uint64
	f.Fuzz(func(t *testing.T, data []byte) {
		spec := decodeFuzzReportSpec(data)
		// distinct client per input:
		// parallel workers must not share challenge budget, and a fresh
		// TOFU baseline keeps the decision a function of this input alone
		clientID := fmt.Sprintf("fuzz-client-%d", clientSeq.Add(1))
		first := verifyOnce(t, clientID, spec)
		// determinism:
		// second submission of the same spec for the same (now-baselined)
		// client must reach the same decision
		second := verifyOnce(t, clientID, spec)
		if first != second {
			t.Fatalf("non-deterministic decision for fixed spec: %v then %v", first, second)
		}
	})
}
