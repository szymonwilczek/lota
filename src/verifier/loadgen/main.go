// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Load Generator - CLI
//
// lota-loadgen drives synthetic agent fleet against a live verifier for scale
// and soak testing.
// See Documentation/performance for the methodology and the soak runbook.
//
//	lota-loadgen setup -dir RIG -agents N [-key-pool K]
//	lota-loadgen run   -dir RIG -server HOST:PORT (-tls-ca FILE | -insecure)
//	                   [-agents N] [-mode steady|storm] [-interval D]
//	                   [-duration D] [-in-flight N] [-timeout D]
//	                   [-out FILE] [-session-log FILE]
//
// Rig directory carries the throwaway attestation CA and the AIK key pool;
// hand ca.crt to the verifier as --aik-ca-cert and policy.yaml as --policy
// so the verifier runs its strict production configuration against the synthetic fleet

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

func main() {
	os.Exit(realMain(os.Args[1:]))
}

func realMain(args []string) int {
	if len(args) < 1 {
		usage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "setup":
		return cmdSetup(args[1:])
	case "run":
		return cmdRun(args[1:])
	case "-h", "-help", "--help", "help":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage(os.Stderr)
		return 2
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, `lota-loadgen - synthetic attestation fleet driver

Commands:
  setup   generate a rig directory (CA, AIK key pool, verifier policy)
  run     drive the fleet against a live verifier

Run 'lota-loadgen <command> -h' for the command's flags.

Typical rig bring-up:
  lota-loadgen setup -dir rig -agents 10000
  lota-verifier -addr :8443 -generate-cert \
    -aik-ca-cert rig/ca.crt -policy rig/policy.yaml \
    -aik-store /var/tmp/loadtest-aiks
  lota-loadgen run -dir rig -server 127.0.0.1:8443 -tls-ca lota-verifier.crt \
    -mode steady -interval 60s -duration 10m -out summary.json

The rig needs the file-backed certificate AIK store: -db selects the SQLite
store, which cannot verify certificate chains, and the verifier refuses to
start with it under the default --require-cert.
`)
}

func cmdSetup(args []string) int {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	dir := fs.String("dir", "", "rig directory to create (required)")
	agents := fs.Int("agents", 1000, "fleet size the rig supports")
	keyPool := fs.Int("key-pool", 0, "AIK RSA key pool size (default min(agents, 256))")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "setup: -dir is required")
		return 2
	}
	start := time.Now()
	if err := writeRig(*dir, *agents, *keyPool); err != nil {
		fmt.Fprintf(os.Stderr, "setup: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "rig ready in %s: %d agents\n", time.Since(start).Round(time.Millisecond), *agents)
	fmt.Fprintf(os.Stderr, "verifier flags: --aik-ca-cert %s --policy %s\n",
		filepath.Join(*dir, rigCACertFile), filepath.Join(*dir, rigPolicyFile))
	return 0
}

func cmdRun(args []string) (code int) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	dir := fs.String("dir", "", "rig directory from setup (required)")
	server := fs.String("server", "", "verifier attestation address host:port (required)")
	tlsCA := fs.String("tls-ca", "", "PEM file with the verifier TLS certificate or its CA")
	insecure := fs.Bool("insecure", false, "skip verifier TLS certificate verification (load rigs only)")
	agents := fs.Int("agents", 0, "agents to drive (default: rig size)")
	mode := fs.String("mode", modeSteady, "steady (interval loop) or storm (one-shot burst)")
	interval := fs.Duration("interval", 60*time.Second, "steady mode attestation interval")
	duration := fs.Duration("duration", 5*time.Minute, "steady mode run length")
	inFlight := fs.Int("in-flight", 128, "storm mode concurrent attestation cap")
	timeout := fs.Duration("timeout", 15*time.Second, "per-attestation deadline (dial to result)")
	progress := fs.Duration("progress", 10*time.Second, "progress line period (0 = quiet)")
	out := fs.String("out", "", "write the JSON summary to this file ('-' = stdout)")
	sessionLog := fs.String("session-log", "", "append per-OK session tokens as JSONL to this file")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *dir == "" || *server == "" {
		fmt.Fprintln(os.Stderr, "run: -dir and -server are required")
		return 2
	}
	tlsCfg, err := clientTLS(*tlsCA, *insecure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return 1
	}

	loadStart := time.Now()
	fleet, meta, err := loadRig(*dir, *agents)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return 1
	}
	n := *agents
	if n <= 0 {
		n = meta.Agents
	}
	fmt.Fprintf(os.Stderr, "rig loaded in %s: %d agents (key pool %d)\n",
		time.Since(loadStart).Round(time.Millisecond), n, meta.KeyPool)

	cfg := &runConfig{
		Server:   *server,
		TLS:      tlsCfg,
		Fleet:    fleet,
		Agents:   n,
		Mode:     *mode,
		Interval: *interval,
		Duration: *duration,
		InFlight: *inFlight,
		Timeout:  *timeout,
		Progress: *progress,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		},
	}
	if *sessionLog != "" {
		f, err := os.OpenFile(*sessionLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "run: open session log: %v\n", err)
			return 1
		}

		// close can surface a short write the writes themselves did not report
		// soak's zero-loss replay reads truncated log as missing tokens,
		// so failed close fails the run
		defer func() {
			if cerr := f.Close(); cerr != nil {
				fmt.Fprintf(os.Stderr, "run: close session log: %v\n", cerr)
				if code == 0 {
					code = 1
				}
			}
		}()
		cfg.SessionsW = f
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	sum, err := run(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run: %v\n", err)
		return 1
	}
	printHuman(sum)
	if *out != "" {
		if err := writeSummary(*out, sum); err != nil {
			fmt.Fprintf(os.Stderr, "run: %v\n", err)
			return 1
		}
	}
	return 0
}

func clientTLS(caFile string, insecure bool) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	switch {
	case insecure:
		cfg.InsecureSkipVerify = true // #nosec G402 -- explicit -insecure opt-in on a load rig
	case caFile != "":
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read -tls-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", caFile)
		}
		cfg.RootCAs = pool
	default:
		return nil, fmt.Errorf("one of -tls-ca or -insecure is required")
	}
	return cfg, nil
}

func writeSummary(path string, sum *summary) error {
	data, err := json.MarshalIndent(sum, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal summary: %w", err)
	}
	data = append(data, '\n')
	if path == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	return nil
}

func printHuman(s *summary) {
	fmt.Fprintf(os.Stderr, "\n=== %s run: %d agents against %s ===\n", s.Mode, s.Agents, s.Server)
	fmt.Fprintf(os.Stderr, "elapsed        %s\n", s.Finished.Sub(s.Started).Round(time.Millisecond))
	fmt.Fprintf(os.Stderr, "attempts       %d\n", s.Attempts)
	fmt.Fprintf(os.Stderr, "verify_ok      %d\n", s.OK)
	for _, k := range sortedKeys(s.Rejected) {
		fmt.Fprintf(os.Stderr, "rejected       %s=%d\n", k, s.Rejected[k])
	}
	for _, k := range sortedKeys(s.TransportError) {
		fmt.Fprintf(os.Stderr, "transport_err  %s=%d\n", k, s.TransportError[k])
	}
	fmt.Fprintf(os.Stderr, "rate           %.1f/s\n", s.RatePerSec)
	fmt.Fprintf(os.Stderr, "latency ms     p50=%.1f p90=%.1f p99=%.1f max=%.1f mean=%.1f\n",
		s.Latency.P50, s.Latency.P90, s.Latency.P99, s.Latency.Max, s.Latency.Mean)
	if s.AgentsNeverOK > 0 {
		fmt.Fprintf(os.Stderr, "agents_never_ok %d\n", s.AgentsNeverOK)
	}
}

func sortedKeys(m map[string]uint64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
