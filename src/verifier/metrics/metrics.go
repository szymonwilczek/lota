// SPDX-License-Identifier: MIT
// LOTA Verifier - Prometheus Metrics
//
// Metrics registry with Prometheus text exposition output.
// Tracks attestation counters, rejection reasons (label-based),
// and verification latency histogram.

package metrics

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// holds all verifier metrics
type Metrics struct {
	// Counters
	AttestationTotal Counter // total attestation attempts
	AttestationOK    Counter // successful attestations
	AttestationFail  Counter // all failed attestations (parse errors + rejections)
	ConnectionErrors Counter // protocol-level errors

	// rejection reason
	Rejections *LabeledCounter

	// verification duration in seconds
	VerifyDuration *Histogram

	// Gauges
	PendingChallenges atomic.Int64
	RegisteredClients atomic.Int64
	ActiveRevocations atomic.Int64
	ActiveBans        atomic.Int64
	UsedNonces        atomic.Int64
	LoadedPolicies    atomic.Int64

	// server start time for uptime calculation
	StartTime time.Time
}

// creates a zeroed metrics registry
func New() *Metrics {
	return &Metrics{
		Rejections: NewLabeledCounter(),
		VerifyDuration: NewHistogram(
			0.001, 0.005, 0.01, 0.025, 0.05,
			0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
		),
		StartTime: time.Now(),
	}
}

// monotonically increasing 64-bit integer
type Counter struct {
	val atomic.Int64
}

func (c *Counter) Inc()         { c.val.Add(1) }
func (c *Counter) Add(n int64)  { c.val.Add(n) }
func (c *Counter) Value() int64 { return c.val.Load() }
func (c *Counter) Reset()       { c.val.Store(0) }

// tracks counts per label value
type LabeledCounter struct {
	mu     sync.RWMutex
	counts map[string]*atomic.Int64
}

func NewLabeledCounter() *LabeledCounter {
	return &LabeledCounter{
		counts: make(map[string]*atomic.Int64),
	}
}

// increments the counter for the given label value
func (lc *LabeledCounter) Inc(label string) {
	lc.mu.RLock()
	counter, ok := lc.counts[label]
	lc.mu.RUnlock()

	if ok {
		counter.Add(1)
		return
	}

	lc.mu.Lock()
	// double-check after acquiring write lock
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

// returns a snapshot of all label->count pairs
func (lc *LabeledCounter) Values() map[string]int64 {
	lc.mu.RLock()
	defer lc.mu.RUnlock()

	result := make(map[string]int64, len(lc.counts))
	for k, v := range lc.counts {
		result[k] = v.Load()
	}
	return result
}

// returns the sum across all labels
func (lc *LabeledCounter) Total() int64 {
	lc.mu.RLock()
	defer lc.mu.RUnlock()

	var total int64
	for _, v := range lc.counts {
		total += v.Load()
	}
	return total
}

// tracks the distribution of observed values
// implements cumulative bucket counting compatible with Prometheus
type Histogram struct {
	mu      sync.Mutex
	bounds  []float64      // upper bounds (sorted), not including +Inf
	buckets []atomic.Int64 // cumulative counts: buckets[i] = count <= bounds[i]
	inf     atomic.Int64   // count of ALL observations (the +Inf bucket)
	sum     atomic.Int64   // sum * 1e9 stored as int64 for atomicity
	count   atomic.Int64
}

// creates a histogram with the given bucket upper bounds
func NewHistogram(bounds ...float64) *Histogram {
	sorted := make([]float64, len(bounds))
	copy(sorted, bounds)
	sort.Float64s(sorted)

	return &Histogram{
		bounds:  sorted,
		buckets: make([]atomic.Int64, len(sorted)),
	}
}

// records a single value into the histogram
func (h *Histogram) Observe(value float64) {
	h.count.Add(1)

	// as fixed-point nanoseconds to avoid float atomics
	h.sum.Add(int64(value * 1e9))

	// increment all buckets where value <= bound
	for i, bound := range h.bounds {
		if value <= bound {
			h.buckets[i].Add(1)
		}
	}
	h.inf.Add(1)
}

// returns the total number of observations
func (h *Histogram) Count() int64 { return h.count.Load() }

// returns the sum of all observed values
func (h *Histogram) Sum() float64 {
	return float64(h.sum.Load()) / 1e9
}

// writes all metrics in Prometheus text exposition format
func (m *Metrics) Export() string {
	var b strings.Builder

	uptime := time.Since(m.StartTime).Seconds()

	writeCounter(&b, "lota_attestations_total",
		"Total number of attestation attempts",
		m.AttestationTotal.Value())

	writeCounter(&b, "lota_attestations_success_total",
		"Total successful attestations",
		m.AttestationOK.Value())

	// labeled rejections
	b.WriteString("# HELP lota_rejections_total Total rejected attestations by reason\n")
	b.WriteString("# TYPE lota_rejections_total counter\n")
	reasons := m.Rejections.Values()
	if len(reasons) == 0 {
		// emit zero-value series for known reasons
		for _, r := range []string{"nonce_fail", "sig_fail", "pcr_fail", "integrity_mismatch", "revoked", "banned"} {
			fmt.Fprintf(&b, "lota_rejections_total{reason=%q} 0\n", r)
		}
	} else {
		// sort for stable output
		keys := make([]string, 0, len(reasons))
		for k := range reasons {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "lota_rejections_total{reason=%q} %d\n", k, reasons[k])
		}
	}
	b.WriteByte('\n')

	writeCounter(&b, "lota_connection_errors_total",
		"Total protocol-level connection errors",
		m.ConnectionErrors.Value())

	// derived counter: total failed attestations across all reasons
	writeCounter(&b, "lota_attestations_failed_total",
		"Total failed attestations (parse errors + rejections)",
		m.AttestationFail.Value())

	// histogram
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

	// gauges
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

// formats a float for Prometheus exposition
func formatFloat(f float64) string {
	if math.IsInf(f, 1) {
		return "+Inf"
	}
	return fmt.Sprintf("%g", f)
}
