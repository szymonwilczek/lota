// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Load Generator - CLI tests

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRealMainUsageAndErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no args", nil, 2},
		{"unknown command", []string{"bogus"}, 2},
		{"help", []string{"help"}, 0},
		{"setup without dir", []string{"setup"}, 2},
		{"run without flags", []string{"run"}, 2},
		{"run without tls choice", []string{"run", "-dir", "x", "-server", "y"}, 1},
	}
	for _, tc := range cases {
		if got := realMain(tc.args); got != tc.want {
			t.Errorf("%s: exit %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestCmdRunMissingRig(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-a-rig")
	code := realMain([]string{"run", "-dir", dir, "-server", "127.0.0.1:1", "-insecure"})
	if code != 1 {
		t.Errorf("run on a missing rig: exit %d, want 1", code)
	}
}

// Whole CLI path:
// setup rig, drive storm against live production server stack, read back the JSON summary
func TestSetupAndRunEndToEnd(t *testing.T) {
	tmp := t.TempDir()
	rigDir := filepath.Join(tmp, "rig")

	if code := realMain([]string{"setup", "-dir", rigDir, "-agents", "3", "-key-pool", "2"}); code != 0 {
		t.Fatalf("setup: exit %d", code)
	}

	fleet, _, err := loadRig(rigDir, 0)
	if err != nil {
		t.Fatalf("loadRig after setup: %v", err)
	}
	addr, _ := startTestServer(t, fleet)

	// startTestServer keeps its TLS material in its own t.TempDir(),
	// so the CLI takes the -insecure path here;
	// TestClientTLS covers -tls-ca certificate verification
	outPath := filepath.Join(tmp, "summary.json")
	sessPath := filepath.Join(tmp, "sessions.jsonl")
	code := realMain([]string{
		"run", "-dir", rigDir, "-server", addr, "-insecure",
		"-mode", "storm", "-in-flight", "2", "-timeout", "10s",
		"-progress", "0", "-out", outPath, "-session-log", sessPath,
	})
	if code != 0 {
		t.Fatalf("run: exit %d", code)
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	var sum summary
	if err := json.Unmarshal(raw, &sum); err != nil {
		t.Fatalf("parse summary: %v", err)
	}
	if sum.OK != 3 || sum.Attempts != 3 || sum.AgentsNeverOK != 0 {
		t.Fatalf("summary: %+v", sum)
	}
	if fi, err := os.Stat(sessPath); err != nil || fi.Size() == 0 {
		t.Errorf("session log missing or empty: %v", err)
	}
}

func TestClientTLS(t *testing.T) {
	if _, err := clientTLS("", false); err == nil {
		t.Error("no CA and no insecure accepted")
	}
	cfg, err := clientTLS("", true)
	if err != nil || !cfg.InsecureSkipVerify {
		t.Errorf("insecure config: %v %+v", err, cfg)
	}
	if _, err := clientTLS(filepath.Join(t.TempDir(), "missing.pem"), false); err == nil {
		t.Error("missing CA file accepted")
	}
	junk := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(junk, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := clientTLS(junk, false); err == nil {
		t.Error("junk CA file accepted")
	}
}

func TestWriteSummaryStdout(t *testing.T) {
	if err := writeSummary("-", &summary{Mode: modeStorm}); err != nil {
		t.Errorf("writeSummary(-): %v", err)
	}
	nested := filepath.Join(t.TempDir(), "no-such-dir", "out.json")
	if err := writeSummary(nested, &summary{}); err == nil {
		t.Error("writeSummary into a missing directory succeeded")
	}
}
