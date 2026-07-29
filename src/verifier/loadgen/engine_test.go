// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Load Generator - Engine tests
//
// E2E tests run a real server.Server (TLS listener, production handleConnection path)
// over a production-shaped Verifier and drive it with the engine,
// so the whole client stack the soak relies on is exercised in-process

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/loadgen/synth"
	"github.com/szymonwilczek/lota/verifier/server"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/verify"
)

// newRigVerifier mirrors the production wiring in src/verifier/main.go:
// certificate-verifying AIK store over the rig CA,
// strict default config,
// generated policy loaded from YAML
func newRigVerifier(t *testing.T, fleet *synth.Fleet) *verify.Verifier {
	t.Helper()
	dir := t.TempDir()

	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, fleet.CA.CertPEM(), 0o600); err != nil {
		t.Fatalf("write CA cert: %v", err)
	}
	aikStore, err := store.NewCertificateStore(filepath.Join(dir, "aiks"), []string{caPath}, true)
	if err != nil {
		t.Fatalf("NewCertificateStore: %v", err)
	}

	// no Close cleanup here:
	// server.Stop closes the verifier it wraps
	v := verify.NewVerifier(verify.DefaultConfig(), aikStore)

	policyYAML, err := fleet.PolicyYAML()
	if err != nil {
		t.Fatalf("PolicyYAML: %v", err)
	}
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, policyYAML, 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := v.LoadPolicy(policyPath); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if err := v.SetActivePolicy(synth.PolicyName); err != nil {
		t.Fatalf("SetActivePolicy: %v", err)
	}
	return v
}

// writeServerTLS mints loopback self-signed server certificate pair
func writeServerTLS(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "lota-loadgen-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write server cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write server key: %v", err)
	}
	return certPath, keyPath
}

// freePort reserves and releases loopback port for the server
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// startTestServer brings up the production attestation listener over fleet's
// verifier and returns its address plus the client TLS config trusting it
func startTestServer(t *testing.T, fleet *synth.Fleet) (addr string, clientTLSCfg *tls.Config) {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := writeServerTLS(t, dir)
	addr = freePort(t)

	cfg := server.DefaultServerConfig()
	cfg.Address = addr
	cfg.CertFile = certPath
	cfg.KeyFile = keyPath

	srv, err := server.NewServer(cfg, newRigVerifier(t, fleet))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(srv.Stop)

	tlsCfg, err := clientTLS(certPath, false)
	if err != nil {
		t.Fatalf("clientTLS: %v", err)
	}
	return addr, tlsCfg
}

func testFleet(t *testing.T, n int) *synth.Fleet {
	t.Helper()
	ca, err := synth.NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	fleet, err := synth.NewFleet(ca, n, 2)
	if err != nil {
		t.Fatalf("NewFleet: %v", err)
	}
	return fleet
}

// Storm drives every agent through one full attestation against the live TLS listener;
// every one must come back VERIFY_OK
func TestStormAgainstLiveServer(t *testing.T) {
	fleet := testFleet(t, 4)
	addr, tlsCfg := startTestServer(t, fleet)

	var sessions bytes.Buffer
	cfg := &runConfig{
		Server:    addr,
		TLS:       tlsCfg,
		Fleet:     fleet,
		Agents:    4,
		Mode:      modeStorm,
		InFlight:  2,
		Timeout:   10 * time.Second,
		SessionsW: &sessions,
	}
	sum, err := run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if sum.OK != 4 || sum.Attempts != 4 {
		t.Fatalf("storm: ok=%d attempts=%d rejected=%v transport=%v",
			sum.OK, sum.Attempts, sum.Rejected, sum.TransportError)
	}
	if sum.AgentsNeverOK != 0 {
		t.Errorf("agents_never_ok = %d, want 0", sum.AgentsNeverOK)
	}
	if sum.Latency.P99 <= 0 || sum.Latency.Max < sum.Latency.P50 {
		t.Errorf("implausible latency stats: %+v", sum.Latency)
	}

	// session log: one valid line per OK with a live token
	lines := bytes.Split(bytes.TrimSpace(sessions.Bytes()), []byte("\n"))
	if len(lines) != 4 {
		t.Fatalf("session log has %d lines, want 4", len(lines))
	}
	var rec sessionRecord
	if err := json.Unmarshal(lines[0], &rec); err != nil {
		t.Fatalf("session log line: %v", err)
	}
	if rec.Token == "" || rec.ValidUntil == 0 || rec.Agent == "" {
		t.Errorf("incomplete session record: %+v", rec)
	}
}

// Steady mode re-attests on the interval:
// with 2 agents over ~1s at 300ms interval every attempt must be OK and each
// agent must attest more than once (registration round + steady rounds)
func TestSteadyAgainstLiveServer(t *testing.T) {
	fleet := testFleet(t, 2)
	addr, tlsCfg := startTestServer(t, fleet)

	cfg := &runConfig{
		Server:   addr,
		TLS:      tlsCfg,
		Fleet:    fleet,
		Agents:   2,
		Mode:     modeSteady,
		Interval: 300 * time.Millisecond,
		Duration: 1 * time.Second,
		Timeout:  10 * time.Second,
	}
	sum, err := run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if sum.OK != sum.Attempts {
		t.Fatalf("steady: ok=%d attempts=%d rejected=%v transport=%v",
			sum.OK, sum.Attempts, sum.Rejected, sum.TransportError)
	}
	if sum.Attempts < 4 {
		t.Errorf("steady attempts = %d, want >= 4 (2 agents x >=2 rounds)", sum.Attempts)
	}
	if sum.IntervalSec != 0.3 {
		t.Errorf("interval_sec = %v, want 0.3", sum.IntervalSec)
	}
	if len(sum.Timeline) == 0 {
		t.Error("steady run produced no timeline")
	}
}

// dead server surfaces as transport errors,
// never as a hang or a crash;
// timeline still records the failures
func TestRunAgainstDeadServer(t *testing.T) {
	fleet := testFleet(t, 2)
	addr := freePort(t) // nothing listens here

	cfg := &runConfig{
		Server:   addr,
		TLS:      &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}, // #nosec G402 -- no listener; connection must fail before TLS
		Fleet:    fleet,
		Agents:   2,
		Mode:     modeStorm,
		Timeout:  2 * time.Second,
		InFlight: 2,
	}
	sum, err := run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if sum.OK != 0 || sum.Attempts != 2 {
		t.Fatalf("dead server: ok=%d attempts=%d", sum.OK, sum.Attempts)
	}
	var transport uint64
	for _, n := range sum.TransportError {
		transport += n
	}
	if transport != 2 {
		t.Errorf("transport errors = %v, want 2 total", sum.TransportError)
	}
	if sum.AgentsNeverOK != 2 {
		t.Errorf("agents_never_ok = %d, want 2", sum.AgentsNeverOK)
	}
}

// interrupted storm keeps what it measured:
// cancellation ends the run like steady mode's duration,
// so the caller still gets summary to print and write to -out
func TestStormCancellationReturnsSummary(t *testing.T) {
	fleet := testFleet(t, 2)
	addr := freePort(t) // nothing listens here

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	sum, err := run(ctx, &runConfig{
		Server:   addr,
		TLS:      &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}, // #nosec G402 -- cancelled before any dial
		Fleet:    fleet,
		Agents:   2,
		Mode:     modeStorm,
		Timeout:  time.Second,
		InFlight: 1,
	})
	if err != nil {
		t.Fatalf("cancelled storm returned an error instead of a summary: %v", err)
	}
	if sum == nil {
		t.Fatal("cancelled storm returned no summary")
	}
	if sum.Mode != modeStorm || sum.Agents != 2 {
		t.Errorf("summary = %+v, want a storm summary over 2 agents", sum)
	}
}

func TestRunConfigValidation(t *testing.T) {
	fleet := testFleet(t, 1)
	base := func() *runConfig {
		return &runConfig{
			Server: "127.0.0.1:1", TLS: &tls.Config{MinVersion: tls.VersionTLS13},
			Fleet: fleet, Agents: 1, Timeout: time.Second,
		}
	}

	cfg := base()
	cfg.Agents = 5 // beyond fleet size
	if _, err := run(context.Background(), cfg); err == nil {
		t.Error("oversized agent count accepted")
	}

	cfg = base()
	cfg.Mode = "bogus"
	if _, err := run(context.Background(), cfg); err == nil {
		t.Error("unknown mode accepted")
	}

	cfg = base()
	cfg.Mode = modeSteady // no interval/duration
	if _, err := run(context.Background(), cfg); err == nil {
		t.Error("steady without interval accepted")
	}
}

func TestErrorKind(t *testing.T) {
	if got := errorKind(fmt.Errorf("dial: %w", errors.New("refused"))); got != "dial" {
		t.Errorf("errorKind(dial) = %q", got)
	}
	if got := errorKind(&net.DNSError{IsTimeout: true}); got != "timeout" {
		t.Errorf("errorKind(timeout) = %q", got)
	}
}
