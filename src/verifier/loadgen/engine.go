// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Load Generator - Load engine

package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/szymonwilczek/lota/verifier/loadgen/synth"
	"github.com/szymonwilczek/lota/verifier/types"
)

type runConfig struct {
	Server   string // attestation listener, host:port
	TLS      *tls.Config
	Fleet    *synth.Fleet
	Agents   int
	Mode     string // "steady" or "storm"
	Interval time.Duration
	Duration time.Duration
	InFlight int           // storm concurrency cap, <= 0 = 128
	Timeout  time.Duration // dial timeout, then again for the exchange
	Progress time.Duration // 0 = quiet
	AttestW  io.Writer     // JSONL log of accepted attestations, may be nil
	Logf     func(format string, args ...any)
}

type secondBucket struct {
	Unix     int64  `json:"unix"`
	OK       uint64 `json:"ok"`
	Rejected uint64 `json:"rejected"`
	Errors   uint64 `json:"errors"`
}

// latencyStats covers verified and refused attestations, in milliseconds.
type latencyStats struct {
	P50  float64 `json:"p50_ms"`
	P90  float64 `json:"p90_ms"`
	P99  float64 `json:"p99_ms"`
	Max  float64 `json:"max_ms"`
	Mean float64 `json:"mean_ms"`
}

type summary struct {
	Mode              string            `json:"mode"`
	Server            string            `json:"server"`
	Agents            int               `json:"agents"`
	IntervalSec       float64           `json:"interval_sec,omitempty"`
	Started           time.Time         `json:"started"`
	Finished          time.Time         `json:"finished"`
	Attempts          uint64            `json:"attempts"`
	OK                uint64            `json:"ok"`
	Rejected          map[string]uint64 `json:"rejected,omitempty"`
	TransportError    map[string]uint64 `json:"transport_errors,omitempty"`
	Latency           latencyStats      `json:"latency"`
	RatePerSec        float64           `json:"achieved_rate_per_sec"`
	AttemptRatePerSec float64           `json:"attempted_rate_per_sec"`
	AgentsNeverOK     int               `json:"agents_never_ok"`
	Timeline          []secondBucket    `json:"timeline,omitempty"`
}

type collector struct {
	mu        sync.Mutex
	attempts  uint64
	ok        uint64
	rejected  map[string]uint64
	transport map[string]uint64
	latencyUs []int64
	timeline  map[int64]*secondBucket
	agentOK   []atomic.Bool
}

func newCollector(agents int) *collector {
	return &collector{
		rejected:  make(map[string]uint64),
		transport: make(map[string]uint64),
		timeline:  make(map[int64]*secondBucket),
		agentOK:   make([]atomic.Bool, agents),
	}
}

func (c *collector) bucket(now time.Time) *secondBucket {
	sec := now.Unix()
	b := c.timeline[sec]
	if b == nil {
		b = &secondBucket{Unix: sec}
		c.timeline[sec] = b
	}
	return b
}

func (c *collector) recordOK(agent int, latency time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts++
	c.ok++
	c.latencyUs = append(c.latencyUs, latency.Microseconds())
	c.bucket(time.Now()).OK++
	c.agentOK[agent].Store(true)
}

func (c *collector) recordRejected(code uint32, latency time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts++
	c.rejected[types.VerifyResultString(code)]++
	c.latencyUs = append(c.latencyUs, latency.Microseconds())
	c.bucket(time.Now()).Rejected++
}

func (c *collector) recordTransport(kind string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts++
	c.transport[kind]++
	c.bucket(time.Now()).Errors++
}

func (c *collector) snapshot() (attempts, ok, errs uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, n := range c.transport {
		errs += n
	}
	return c.attempts, c.ok, errs
}

func (c *collector) summarize(cfg *runConfig, started, finished time.Time) *summary {
	c.mu.Lock()
	defer c.mu.Unlock()

	s := &summary{
		Mode:           cfg.Mode,
		Server:         cfg.Server,
		Agents:         cfg.Agents,
		Started:        started,
		Finished:       finished,
		Attempts:       c.attempts,
		OK:             c.ok,
		Rejected:       c.rejected,
		TransportError: c.transport,
	}
	if cfg.Mode == modeSteady {
		s.IntervalSec = cfg.Interval.Seconds()
	}

	elapsed := finished.Sub(started).Seconds()
	if elapsed > 0 {
		s.RatePerSec = float64(c.ok) / elapsed
		s.AttemptRatePerSec = float64(c.attempts) / elapsed
	}
	for i := range c.agentOK {
		if !c.agentOK[i].Load() {
			s.AgentsNeverOK++
		}
	}

	if len(c.latencyUs) > 0 {
		lat := slices.Clone(c.latencyUs)
		slices.Sort(lat)
		var sum int64
		for _, v := range lat {
			sum += v
		}
		pct := func(p float64) float64 {
			idx := int(p*float64(len(lat)-1) + 0.5)
			return float64(lat[idx]) / 1000.0
		}
		s.Latency = latencyStats{
			P50:  pct(0.50),
			P90:  pct(0.90),
			P99:  pct(0.99),
			Max:  float64(lat[len(lat)-1]) / 1000.0,
			Mean: float64(sum) / float64(len(lat)) / 1000.0,
		}
	}

	secs := make([]int64, 0, len(c.timeline))
	for sec := range c.timeline {
		secs = append(secs, sec)
	}
	slices.Sort(secs)
	for _, sec := range secs {
		s.Timeline = append(s.Timeline, *c.timeline[sec])
	}
	return s
}

const (
	modeSteady = "steady"
	modeStorm  = "storm"
)

type attestRecord struct {
	Agent      string `json:"agent"`
	Unix       int64  `json:"unix"`
	ValidUntil uint64 `json:"valid_until"`
}

func run(ctx context.Context, cfg *runConfig) (*summary, error) {
	if cfg.Agents <= 0 || cfg.Agents > len(cfg.Fleet.Agents) {
		return nil, fmt.Errorf("agent count %d outside fleet size %d", cfg.Agents, len(cfg.Fleet.Agents))
	}
	col := newCollector(cfg.Agents)
	var (
		attestMu  sync.Mutex
		attestErr error // first attestation log write error
	)

	attest := func(agent int) {
		a := cfg.Fleet.Agents[agent]
		start := time.Now()
		result, err := attestOnce(cfg, a)
		latency := time.Since(start)
		switch {
		case err != nil:
			col.recordTransport(errorKind(err))
		case result.Result == types.VerifyOK:
			col.recordOK(agent, latency)
			if cfg.AttestW != nil {
				line, merr := json.Marshal(attestRecord{
					Agent:      a.Name,
					Unix:       time.Now().Unix(),
					ValidUntil: result.ValidUntil,
				})
				if merr == nil {
					line = append(line, '\n')
					attestMu.Lock()
					_, werr := cfg.AttestW.Write(line)
					if attestErr == nil {
						attestErr = werr
					}
					attestMu.Unlock()
				}
			}
		default:
			col.recordRejected(result.Result, latency)
		}
	}

	started := time.Now()
	stopProgress := startProgress(cfg, col)

	var err error
	switch cfg.Mode {
	case modeSteady:
		err = runSteady(ctx, cfg, attest)
	case modeStorm:
		runStorm(ctx, cfg, attest)
	default:
		err = fmt.Errorf("unknown mode %q", cfg.Mode)
	}
	stopProgress()
	if err != nil {
		return nil, err
	}
	if attestErr != nil {
		return nil, fmt.Errorf("write attestation log: %w", attestErr)
	}
	return col.summarize(cfg, started, time.Now()), nil
}

// runSteady spreads the agents' first attestation across one interval,
// then repeats each on the interval until the duration elapses.
func runSteady(ctx context.Context, cfg *runConfig, attest func(agent int)) error {
	if cfg.Interval <= 0 {
		return fmt.Errorf("steady mode needs a positive interval")
	}
	if cfg.Duration <= 0 {
		return fmt.Errorf("steady mode needs a positive duration")
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Duration)
	defer cancel()

	var wg sync.WaitGroup
	for i := range cfg.Agents {
		offset := cfg.Interval * time.Duration(i) / time.Duration(cfg.Agents)
		wg.Go(func() {
			t := time.NewTimer(offset)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			ticker := time.NewTicker(cfg.Interval)
			defer ticker.Stop()
			for {
				attest(i)
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		})
	}
	wg.Wait()
	return nil
}

// runStorm attests every agent once, at most InFlight at a time.
// Cancellation stops launching but is no failure, so the agents that did
// attest are still summarized.
func runStorm(ctx context.Context, cfg *runConfig, attest func(agent int)) {
	inFlight := cfg.InFlight
	if inFlight <= 0 {
		inFlight = 128
	}
	sem := make(chan struct{}, inFlight)
	var wg sync.WaitGroup
	for i := range cfg.Agents {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case sem <- struct{}{}:
		}
		wg.Go(func() {
			defer func() { <-sem }()
			attest(i)
		})
	}
	wg.Wait()
}

func attestOnce(cfg *runConfig, a *synth.Agent) (*types.VerifyResult, error) {
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", cfg.Server, cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(cfg.Timeout)); err != nil {
		return nil, fmt.Errorf("deadline: %w", err)
	}

	chBuf := make([]byte, 48)
	if _, err := io.ReadFull(conn, chBuf); err != nil {
		return nil, fmt.Errorf("read challenge: %w", err)
	}
	if magic := binary.LittleEndian.Uint32(chBuf[0:4]); magic != types.ReportMagic {
		return nil, fmt.Errorf("read challenge: bad magic 0x%08X", magic)
	}
	var nonce [types.NonceSize]byte
	copy(nonce[:], chBuf[8:40])

	report, err := cfg.Fleet.BuildReport(a, nonce)
	if err != nil {
		return nil, fmt.Errorf("build report: %w", err)
	}
	if _, err := conn.Write(report); err != nil {
		return nil, fmt.Errorf("write report: %w", err)
	}

	resBuf := make([]byte, 24)
	if _, err := io.ReadFull(conn, resBuf); err != nil {
		return nil, fmt.Errorf("read result: %w", err)
	}
	result := &types.VerifyResult{
		Magic:      binary.LittleEndian.Uint32(resBuf[0:4]),
		Version:    binary.LittleEndian.Uint32(resBuf[4:8]),
		Result:     binary.LittleEndian.Uint32(resBuf[8:12]),
		Flags:      binary.LittleEndian.Uint32(resBuf[12:16]),
		ValidUntil: binary.LittleEndian.Uint64(resBuf[16:24]),
	}
	return result, nil
}

// errorKind names a transport error by its timeout or by the text before
// its first colon.
func errorKind(err error) string {
	var netErr net.Error
	switch {
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	default:
		msg := err.Error()
		for i, r := range msg {
			if r == ':' {
				return msg[:i]
			}
		}
		return msg
	}
}

func startProgress(cfg *runConfig, col *collector) (stop func()) {
	if cfg.Progress <= 0 || cfg.Logf == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(cfg.Progress)
		defer ticker.Stop()
		start := time.Now()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				attempts, ok, errs := col.snapshot()
				elapsed := time.Since(start)
				cfg.Logf("t=%s attempts=%d ok=%d errors=%d rate=%.1f/s verified",
					elapsed.Round(time.Second), attempts, ok, errs,
					float64(ok)/elapsed.Seconds())
			}
		}
	}()
	return func() { close(done) }
}
