// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
package server

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/logging"
	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/verify"
)

// startProbedServer brings up the attestation listener and hands back the address
// together with the two counters a health check must not move.
func startProbedServer(t *testing.T) (string, *metrics.Metrics, *verify.Verifier) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	cfg := ServerConfig{
		Address:      addr,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 10 * time.Second,
		Logger:       logging.Nop(),
		Metrics:      metrics.New(),
	}
	cfg.CertFile, cfg.KeyFile = writeTestTLSPair(t)

	vcfg := verify.DefaultConfig()
	vcfg.RequireBootEnrollment = false
	vcfg.Metrics = metrics.New()
	v := verify.NewVerifier(vcfg, store.NewMemoryStore())

	srv, err := NewServer(cfg, v)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(srv.Stop)

	return addr, cfg.Metrics, v
}

// A TCP health check (e.g. the chart's probes) connects and closes without
// speaking; it must raise no connection error and leave no challenge pending.
func TestBareConnectIsNotAFailedAttestation(t *testing.T) {
	const probes = 20

	addr, m, v := startProbedServer(t)

	for range probes {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		conn.Close()
	}

	// The server sees each close on its own schedule, so give it time to
	// register what the probes cost. Anything moving ends the wait early;
	// a run that stays at zero waits it out.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m.ConnectionErrors.Value() > 0 || v.Stats().PendingChallenges > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if got := m.ConnectionErrors.Value(); got != 0 {
		t.Errorf("%d probe connections raised %d connection errors, want 0",
			probes, got)
	}

	if got := v.Stats().PendingChallenges; got != 0 {
		t.Errorf("%d probe connections left %d challenges pending, want 0",
			probes, got)
	}
}

// A checker that completes TLS, reads the challenge and closes without a report
// raises no connection error, and its challenge is released, not left to expire.
func TestUnansweredChallengeIsReleased(t *testing.T) {
	const probes = 10

	addr, m, v := startProbedServer(t)
	tlsCfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13} // #nosec G402 -- self-signed loopback listener under test

	for range probes {
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		var challenge [48]byte
		if _, err := readFullConn(conn, challenge[:]); err != nil {
			t.Fatalf("read challenge: %v", err)
		}
		conn.Close()
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if m.ConnectionErrors.Value() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if got := m.ConnectionErrors.Value(); got != 0 {
		t.Errorf("%d unanswered challenges raised %d connection errors, want 0",
			probes, got)
	}

	if got := v.Stats().PendingChallenges; got != 0 {
		t.Errorf("%d unanswered challenges left %d pending, want 0", probes, got)
	}
}
