// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package metrics

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

func TestCounter(t *testing.T) {
	var c Counter
	if c.Value() != 0 {
		t.Fatal("new counter should be 0")
	}

	c.Inc()
	c.Inc()
	c.Add(3)
	if c.Value() != 5 {
		t.Errorf("expected 5, got %d", c.Value())
	}
}

func TestLabeledCounter(t *testing.T) {
	lc := NewLabeledCounter()

	lc.Inc("nonce_fail")
	lc.Inc("nonce_fail")
	lc.Inc("sig_fail")

	vals := lc.Values()
	if vals["nonce_fail"] != 2 {
		t.Errorf("expected nonce_fail=2, got %d", vals["nonce_fail"])
	}
	if vals["sig_fail"] != 1 {
		t.Errorf("expected sig_fail=1, got %d", vals["sig_fail"])
	}
	if lc.Total() != 3 {
		t.Errorf("expected total=3, got %d", lc.Total())
	}
}

func TestLabeledCounter_Concurrent(t *testing.T) {
	lc := NewLabeledCounter()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lc.Inc("concurrent")
		}()
	}
	wg.Wait()

	if lc.Total() != 100 {
		t.Errorf("expected 100, got %d", lc.Total())
	}
}

func TestHistogram(t *testing.T) {
	h := NewHistogram(0.01, 0.05, 0.1, 0.5, 1.0)

	h.Observe(0.005)
	h.Observe(0.042)
	h.Observe(0.75)
	h.Observe(2.0)

	if h.Count() != 4 {
		t.Errorf("expected count=4, got %d", h.Count())
	}

	// 0.005 + 0.042 + 0.75 + 2.0 = 2.797
	sum := h.Sum()
	if sum < 2.79 || sum > 2.80 {
		t.Errorf("expected sum ~2.797, got %f", sum)
	}

	// bucket checks (cumulative)
	if v := h.buckets[0].Load(); v != 1 { // <= 0.01
		t.Errorf("bucket[0.01] = %d, want 1", v)
	}
	if v := h.buckets[1].Load(); v != 2 { // <= 0.05
		t.Errorf("bucket[0.05] = %d, want 2", v)
	}
	if v := h.buckets[4].Load(); v != 3 { // <= 1.0
		t.Errorf("bucket[1.0] = %d, want 3", v)
	}
	if v := h.inf.Load(); v != 4 { // +Inf (all)
		t.Errorf("bucket[+Inf] = %d, want 4", v)
	}
}

func TestHistogram_Concurrent(t *testing.T) {
	h := NewHistogram(0.1, 0.5, 1.0)
	var wg sync.WaitGroup

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(v float64) {
			defer wg.Done()
			h.Observe(v)
		}(float64(i) / 1000.0)
	}
	wg.Wait()

	if h.Count() != 1000 {
		t.Errorf("expected 1000 observations, got %d", h.Count())
	}
}

func TestExport_Format(t *testing.T) {
	m := New()

	m.AttestationTotal.Add(100)
	m.AttestationOK.Add(95)
	m.Rejections.Inc("nonce_fail")
	m.Rejections.Inc("nonce_fail")
	m.Rejections.Inc("sig_fail")
	m.Rejections.Inc("revoked")
	m.VerifyDuration.Observe(0.042)
	m.VerifyDuration.Observe(0.105)
	m.PendingChallenges.Store(3)
	m.RegisteredClients.Store(10)
	m.ActiveRevocations.Store(1)
	m.ActiveBans.Store(2)

	output := m.Export()

	checks := []string{
		"lota_attestations_total 100",
		"lota_attestations_success_total 95",
		`lota_rejections_total{reason="nonce_fail"} 2`,
		`lota_rejections_total{reason="sig_fail"} 1`,
		`lota_rejections_total{reason="revoked"} 1`,
		"# TYPE lota_verification_duration_seconds histogram",
		`lota_verification_duration_seconds_bucket{le="+Inf"} 2`,
		"lota_verification_duration_seconds_count 2",
		"lota_pending_challenges 3",
		"lota_registered_clients 10",
		"lota_active_revocations 1",
		"lota_active_bans 2",
		"# TYPE lota_uptime_seconds gauge",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("expected %q in output, not found.\nFull output:\n%s", check, output)
		}
	}

	typeChecks := []string{
		"# TYPE lota_attestations_total counter",
		"# TYPE lota_rejections_total counter",
		"# TYPE lota_verification_duration_seconds histogram",
		"# TYPE lota_pending_challenges gauge",
	}
	for _, check := range typeChecks {
		if !strings.Contains(output, check) {
			t.Errorf("expected %q in output", check)
		}
	}
}

// Every verdict reason needs a zero series before it first fires, or alerts
// on it read "no data" on a fresh verifier.
// Seed from the verdict vocabulary, not a hand-kept list.
func TestExport_SeedsEveryVerdictReason(t *testing.T) {
	unknown := regexp.MustCompile(`^unknown_[0-9]+$`)
	output := New().Export()

	for code := uint32(1); code < 64; code++ {
		reason := types.VerifyResultString(code)
		if unknown.MatchString(reason) {
			continue
		}
		want := fmt.Sprintf("lota_rejections_total{reason=%q} 0", reason)
		if !strings.Contains(output, want) {
			t.Errorf("verdict %d (%s) can refuse a round and has no series until it first fires",
				code, reason)
		}
	}
}

func TestExport_EmptyRejections(t *testing.T) {
	m := New()
	output := m.Export()

	// should emit zero-value series for known reasons
	checks := []string{
		`lota_rejections_total{reason="nonce_fail"} 0`,
		`lota_rejections_total{reason="sig_fail"} 0`,
		`lota_rejections_total{reason="revoked"} 0`,
		`lota_rejections_total{reason="banned"} 0`,
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("expected zero-value %q in output", check)
		}
	}
}

// verify path counts self-service re-anchor outcomes,
// the monitoring API the operator-forced ones, and every rejection reason,
// so all must reach the exposition output:
// operator alerting on escalations or baseline errors needs the series to exist
// (zero-valued when nothing happened yet, so absence-blind alert expressions still match)
func TestExport_ReanchorOutcomes(t *testing.T) {
	m := New()

	output := m.Export()
	for _, outcome := range []string{"strong", "lfa", "forced", "escalate"} {
		want := `lota_reanchors_total{outcome="` + outcome + `"} 0`
		if !strings.Contains(output, want) {
			t.Errorf("expected zero-value %q in output", want)
		}
	}
	if !strings.Contains(output, `lota_rejections_total{reason="baseline_error"} 0`) {
		t.Errorf("expected zero-value baseline_error rejection series")
	}

	m.Reanchors.Inc("strong")
	m.Reanchors.Inc("forced")
	m.Reanchors.Inc("escalate")
	m.Reanchors.Inc("escalate")

	output = m.Export()
	checks := []string{
		"# TYPE lota_reanchors_total counter",
		`lota_reanchors_total{outcome="strong"} 1`,
		`lota_reanchors_total{outcome="forced"} 1`,
		`lota_reanchors_total{outcome="escalate"} 2`,
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("expected %q in output, not found.\nFull output:\n%s", check, output)
		}
	}
}

func TestExport_AttestationLogLoss(t *testing.T) {
	m := New()

	output := m.Export()
	for _, want := range []string{
		"lota_attestation_log_dropped_total 0",
		"lota_attestation_log_failed_total 0",
		"lota_attestation_log_events_lost_total 0",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("expected zero-value %q in output", want)
		}
	}

	m.AttestationRecordsDropped(3)
	m.AttestationRecordsDropped(2)
	m.AttestationRecordsFailed(4)
	m.AttestationEventsLost(1)
	m.AttestationEventsLost(2)

	output = m.Export()
	checks := []string{
		"# TYPE lota_attestation_log_dropped_total counter",
		"lota_attestation_log_dropped_total 5",
		"# TYPE lota_attestation_log_failed_total counter",
		"lota_attestation_log_failed_total 4",
		"# TYPE lota_attestation_log_events_lost_total counter",
		"lota_attestation_log_events_lost_total 3",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("expected %q in output, not found.\nFull output:\n%s", check, output)
		}
	}
}
