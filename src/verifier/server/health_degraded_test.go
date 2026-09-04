// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - /health answering for the listener it reports on

package server

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/logging"
	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/verify"
)

// freeLoopbackAddr returns an unused loopback address for the server to bind.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}

// startHealthServer starts both listeners on loopback and returns the server
// and the API base URL.
func startHealthServer(t *testing.T, drain time.Duration) (*Server, string) {
	t.Helper()

	httpAddr := freeLoopbackAddr(t)
	cfg := DefaultServerConfig()
	cfg.Address = "127.0.0.1:0"
	cfg.HTTPAddress = httpAddr
	cfg.Logger = logging.Nop()
	cfg.Metrics = metrics.New()
	cfg.ShutdownDrain = drain
	cfg.CertFile, cfg.KeyFile = writeTestTLSPair(t)

	vcfg := verify.DefaultConfig()
	vcfg.RequireBootEnrollment = false
	vcfg.Metrics = cfg.Metrics
	v := verify.NewVerifier(vcfg, store.NewMemoryStore())

	srv, err := NewServer(cfg, v)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return srv, "http://" + httpAddr
}

// health reads /health and returns the status code and the parsed body.
func health(t *testing.T, base string) (int, healthResponse) {
	t.Helper()

	resp, err := http.Get(base + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /health: %v", err)
	}
	var parsed healthResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("decode /health (%q): %v", body, err)
	}
	return resp.StatusCode, parsed
}

// /health reports degraded once the attestation listener is gone.
func TestHealthTurnsDegradedWhenTheAttestationListenerIsGone(t *testing.T) {
	srv, base := startHealthServer(t, 0)
	t.Cleanup(srv.Stop)

	if code, body := health(t, base); code != http.StatusOK || body.Status != "ok" {
		t.Fatalf("healthy verifier answered %d %q, want 200 ok", code, body.Status)
	}

	// the listener dies under the accept loop, which is what a closed socket
	// looks like from inside the process
	if err := srv.listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	var code int
	var body healthResponse
	for time.Now().Before(deadline) {
		code, body = health(t, base)
		if code != http.StatusOK {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if code != http.StatusServiceUnavailable || body.Status != "degraded" {
		t.Fatalf("/health with no attestation listener answered %d %q, want 503 degraded",
			code, body.Status)
	}
	if body.TLS.Listening {
		t.Error("/health reports the attestation listener as up after it was closed")
	}
}

// On shutdown the attestation listener closes first and /health answers
// degraded through the drain.
func TestShutdownDrainsWithTheAPIStillAnswering(t *testing.T) {
	srv, base := startHealthServer(t, 750*time.Millisecond)
	attestAddr := srv.listener.Addr().String()

	stopped := make(chan struct{})
	go func() {
		srv.Stop()
		close(stopped)
	}()

	// while draining: the attestation port is gone and /health says so
	deadline := time.Now().Add(2 * time.Second)
	sawDegraded := false
	for time.Now().Before(deadline) {
		code, body := health(t, base)
		if code == http.StatusServiceUnavailable && body.Status == "degraded" {
			sawDegraded = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !sawDegraded {
		t.Error("/health never answered degraded while the verifier was draining")
	}

	if conn, err := net.DialTimeout("tcp", attestAddr, 500*time.Millisecond); err == nil {
		conn.Close()
		t.Error("the attestation listener still accepts during the drain")
	}

	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return")
	}

	if resp, err := http.Get(base + "/health"); err == nil {
		resp.Body.Close()
		t.Error("the API still answers after the drain ended")
	}
}
