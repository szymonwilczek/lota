// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Prometheus Metrics

package metrics

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// Metrics holds the verifier counters, gauges and latency histogram.
// The gauges are not updated here; the caller stores them before Export.
type Metrics struct {
	AttestationTotal Counter
	AttestationOK    Counter
	AttestationFail  Counter
	ConnectionErrors Counter

	AttestationLogDropped    Counter
	AttestationLogFailed     Counter
	AttestationLogEventsLost Counter

	Rejections *LabeledCounter

	Reanchors *LabeledCounter

	VerifyDuration *Histogram // seconds

	PendingChallenges atomic.Int64
	RegisteredClients atomic.Int64
	ActiveRevocations atomic.Int64
	ActiveBans        atomic.Int64
	UsedNonces        atomic.Int64
	LoadedPolicies    atomic.Int64

	StartTime time.Time
}

// New returns a zeroed registry with latency buckets from 1 ms to 10 s.
func New() *Metrics {
	return &Metrics{
		Rejections: NewLabeledCounter(),
		Reanchors:  NewLabeledCounter(),
		VerifyDuration: NewHistogram(
			0.001, 0.005, 0.01, 0.025, 0.05,
			0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
		),
		StartTime: time.Now(),
	}
}

// Counter is an atomic int64 count.
type Counter struct {
	val atomic.Int64
}

func (c *Counter) Inc()         { c.val.Add(1) }
func (c *Counter) Add(n int64)  { c.val.Add(n) }
func (c *Counter) Value() int64 { return c.val.Load() }

// LabeledCounter keeps a count per label value.
type LabeledCounter struct {
	mu     sync.RWMutex
	counts map[string]*atomic.Int64
}

// NewLabeledCounter returns an empty LabeledCounter.
func NewLabeledCounter() *LabeledCounter {
	return &LabeledCounter{
		counts: make(map[string]*atomic.Int64),
	}
}

// Inc adds one to the count for label.
func (lc *LabeledCounter) Inc(label string) {
	lc.mu.RLock()
	counter, ok := lc.counts[label]
	lc.mu.RUnlock()

	if ok {
		counter.Add(1)
		return
	}

	lc.mu.Lock()
	if counter, ok = lc.counts[label]; ok {
		lc.mu.Unlock()
		counter.Add(1)
		return
	}
	counter = &atomic.Int64{}
	counter.Store(1)
	lc.counts[label] = counter
	lc.mu.Unlock()
}

// Values returns a copy of the counts.
func (lc *LabeledCounter) Values() map[string]int64 {
	lc.mu.RLock()
	defer lc.mu.RUnlock()

	result := make(map[string]int64, len(lc.counts))
	for k, v := range lc.counts {
		result[k] = v.Load()
	}
	return result
}

// Histogram counts observations into cumulative buckets.
type Histogram struct {
	bounds  []float64      // sorted, +Inf implied
	buckets []atomic.Int64 // buckets[i] counts values <= bounds[i]
	inf     atomic.Int64
	sum     atomic.Int64 // sum of values * 1e9, an integer to stay atomic
	count   atomic.Int64
}

// NewHistogram returns a histogram over the given bucket upper bounds.
func NewHistogram(bounds ...float64) *Histogram {
	sorted := make([]float64, len(bounds))
	copy(sorted, bounds)
	sort.Float64s(sorted)

	return &Histogram{
		bounds:  sorted,
		buckets: make([]atomic.Int64, len(sorted)),
	}
}

// Observe records value.
func (h *Histogram) Observe(value float64) {
	h.count.Add(1)

	h.sum.Add(int64(value * 1e9))

	for i, bound := range h.bounds {
		if value <= bound {
			h.buckets[i].Add(1)
		}
	}
	h.inf.Add(1)
}

// Count returns the number of observations.
func (h *Histogram) Count() int64 { return h.count.Load() }

// Sum returns the sum of observed values, each truncated to 1e-9.
func (h *Histogram) Sum() float64 {
	return float64(h.sum.Load()) / 1e9
}

// rejection labels that name no verdict
var internalRejectionReasons = []string{"baseline_error"}

// Export renders the metrics in the Prometheus text exposition format.
func (m *Metrics) Export() string {
	var b strings.Builder

	uptime := time.Since(m.StartTime).Seconds()

	writeCounter(&b, "lota_attestations_total",
		"Total number of attestation attempts",
		m.AttestationTotal.Value())

	writeCounter(&b, "lota_attestations_success_total",
		"Total successful attestations",
		m.AttestationOK.Value())

	writeLabeledCounter(&b, "lota_rejections_total",
		"Total rejected attestations by reason", "reason",
		m.Rejections.Values(),
		append(types.RejectionReasons(), internalRejectionReasons...))

	writeLabeledCounter(&b, "lota_reanchors_total",
		"Total baseline re-anchors by outcome", "outcome",
		m.Reanchors.Values(),
		[]string{"strong", "lfa", "mok", "forced", "escalate"})

	writeCounter(&b, "lota_connection_errors_total",
		"Total protocol-level connection errors",
		m.ConnectionErrors.Value())

	writeCounter(&b, "lota_attestation_log_dropped_total",
		"Decision records dropped because the log buffer was full",
		m.AttestationLogDropped.Value())

	writeCounter(&b, "lota_attestation_log_failed_total",
		"Decision records lost to a failed log write",
		m.AttestationLogFailed.Value())

	writeCounter(&b, "lota_attestation_log_events_lost_total",
		"Lost decision records that were events rather than trusted rounds",
		m.AttestationLogEventsLost.Value())

	writeCounter(&b, "lota_attestations_failed_total",
		"Total failed attestations (parse errors + rejections)",
		m.AttestationFail.Value())

	b.WriteString("# HELP lota_verification_duration_seconds Attestation verification latency\n")
	b.WriteString("# TYPE lota_verification_duration_seconds histogram\n")
	for i, bound := range m.VerifyDuration.bounds {
		le := formatFloat(bound)
		fmt.Fprintf(&b, "lota_verification_duration_seconds_bucket{le=%q} %d\n",
			le, m.VerifyDuration.buckets[i].Load())
	}
	fmt.Fprintf(&b, "lota_verification_duration_seconds_bucket{le=\"+Inf\"} %d\n",
		m.VerifyDuration.inf.Load())
	fmt.Fprintf(&b, "lota_verification_duration_seconds_sum %s\n",
		formatFloat(m.VerifyDuration.Sum()))
	fmt.Fprintf(&b, "lota_verification_duration_seconds_count %d\n\n",
		m.VerifyDuration.Count())

	writeGauge(&b, "lota_pending_challenges",
		"Number of outstanding attestation challenges",
		m.PendingChallenges.Load())

	writeGauge(&b, "lota_registered_clients",
		"Number of registered attestation clients",
		m.RegisteredClients.Load())

	writeGauge(&b, "lota_active_revocations",
		"Number of currently revoked client AIKs",
		m.ActiveRevocations.Load())

	writeGauge(&b, "lota_active_bans",
		"Number of currently banned hardware IDs",
		m.ActiveBans.Load())

	writeGauge(&b, "lota_used_nonces",
		"Number of consumed nonces in replay history",
		m.UsedNonces.Load())

	writeGauge(&b, "lota_loaded_policies",
		"Number of loaded PCR policies",
		m.LoadedPolicies.Load())

	writeGauge(&b, "lota_uptime_seconds",
		"Verifier uptime in seconds",
		int64(uptime))

	return b.String()
}

// writeLabeledCounter emits a series per recorded label and a zero series
// for each known label not yet recorded, so an alert finds a series to match.
func writeLabeledCounter(b *strings.Builder, name, help, label string,
	values map[string]int64, known []string,
) {
	fmt.Fprintf(b, "# HELP %s %s\n", name, help)
	fmt.Fprintf(b, "# TYPE %s counter\n", name)
	merged := make(map[string]int64, len(values)+len(known))
	for _, k := range known {
		merged[k] = 0
	}
	for k, v := range values {
		merged[k] = v
	}
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(b, "%s{%s=%q} %d\n", name, label, k, merged[k])
	}
	b.WriteByte('\n')
}

func writeCounter(b *strings.Builder, name, help string, value int64) {
	fmt.Fprintf(b, "# HELP %s %s\n", name, help)
	fmt.Fprintf(b, "# TYPE %s counter\n", name)
	fmt.Fprintf(b, "%s %d\n\n", name, value)
}

func writeGauge(b *strings.Builder, name, help string, value int64) {
	fmt.Fprintf(b, "# HELP %s %s\n", name, help)
	fmt.Fprintf(b, "# TYPE %s gauge\n", name)
	fmt.Fprintf(b, "%s %d\n\n", name, value)
}

func formatFloat(f float64) string {
	if math.IsInf(f, 1) {
		return "+Inf"
	}
	return fmt.Sprintf("%g", f)
}

// Metrics implements store.AttestationLogLoss.
func (m *Metrics) AttestationRecordsDropped(n int64) { m.AttestationLogDropped.Add(n) }
func (m *Metrics) AttestationRecordsFailed(n int64)  { m.AttestationLogFailed.Add(n) }
func (m *Metrics) AttestationEventsLost(n int64)     { m.AttestationLogEventsLost.Add(n) }
