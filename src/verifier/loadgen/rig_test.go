// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Load Generator - Rig directory tests

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRigRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rig")
	if err := writeRig(dir, 5, 2, ""); err != nil {
		t.Fatalf("writeRig: %v", err)
	}
	for _, name := range []string{rigCACertFile, rigCAKeyFile, rigKeysFile, rigPolicyFile, rigMetaFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("missing rig file %s: %v", name, err)
		}
	}

	fleet, meta, err := loadRig(dir, 0)
	if err != nil {
		t.Fatalf("loadRig: %v", err)
	}
	if meta.Agents != 5 || meta.KeyPool != 2 {
		t.Errorf("meta = %+v, want 5 agents / 2 keys", meta)
	}
	if len(fleet.Agents) != 5 {
		t.Errorf("fleet size %d, want 5", len(fleet.Agents))
	}

	// identities must be stable across loads:
	// the verifier's baselines key on them
	fleet2, _, err := loadRig(dir, 3)
	if err != nil {
		t.Fatalf("loadRig(3): %v", err)
	}
	if len(fleet2.Agents) != 3 {
		t.Errorf("partial fleet size %d, want 3", len(fleet2.Agents))
	}
	for i := range fleet2.Agents {
		if fleet2.Agents[i].Pseudonym != fleet.Agents[i].Pseudonym {
			t.Errorf("agent %d pseudonym changed across loads", i)
		}
		if !fleet2.Agents[i].Key.Equal(fleet.Agents[i].Key) {
			t.Errorf("agent %d key changed across loads", i)
		}
	}
}

func TestRigSetupAgainSetsModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rig")
	if err := writeRig(dir, 2, 1, ""); err != nil {
		t.Fatalf("writeRig: %v", err)
	}
	want := map[string]os.FileMode{
		rigCACertFile: 0o644, rigCAKeyFile: 0o600, rigKeysFile: 0o600,
		rigPolicyFile: 0o644, rigMetaFile: 0o644,
	}
	for name := range want {
		path := filepath.Join(dir, name)
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	oldKey, err := os.ReadFile(filepath.Join(dir, rigCAKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	// a reader that opened ca.key while it was 0666
	held, err := os.Open(filepath.Join(dir, rigCAKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	if err := writeRig(dir, 2, 1, ""); err != nil {
		t.Fatalf("writeRig again: %v", err)
	}
	got, err := io.ReadAll(held)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(oldKey) {
		t.Error("a descriptor opened before setup reads the new CA key")
	}
	want["."] = os.ModeDir | 0o700
	for name, mode := range want {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode() & (os.ModeDir | os.ModePerm); got != mode {
			t.Errorf("%s mode %v, want %v", name, got, mode)
		}
	}
}

func TestLoadRigRejectsOversizedFleet(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rig")
	if err := writeRig(dir, 2, 1, ""); err != nil {
		t.Fatalf("writeRig: %v", err)
	}
	if _, _, err := loadRig(dir, 10); err == nil {
		t.Error("loadRig accepted more agents than the rig was set up with")
	}
}

// A damaged PEM block drops out of the key pool without an error of its
// own, so the rig is refused on the count rig.json records.
func TestLoadRigRejectsDamagedKeyPool(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rig")
	if err := writeRig(dir, 5, 3, ""); err != nil {
		t.Fatalf("writeRig: %v", err)
	}
	path := filepath.Join(dir, rigKeysFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// break the base64 of the middle block
	const begin = "-----BEGIN PRIVATE KEY-----\n"
	blocks := strings.SplitAfter(string(data),
		"-----END PRIVATE KEY-----\n")
	if len(blocks) < 3 || !strings.HasPrefix(blocks[1], begin) {
		t.Fatalf("unexpected key pool layout: %d blocks", len(blocks))
	}
	blocks[1] = begin + "!" + blocks[1][len(begin)+1:]
	if err := os.WriteFile(path, []byte(strings.Join(blocks, "")),
		0o600); err != nil {
		t.Fatal(err)
	}

	_, _, err = loadRig(dir, 0)
	if err == nil || !strings.Contains(err.Error(), "2 of 3 keys") {
		t.Fatalf("loadRig: %v, want the damaged pool refused", err)
	}
}

func TestLoadRigMissingDir(t *testing.T) {
	if _, _, err := loadRig(filepath.Join(t.TempDir(), "nope"), 0); err == nil {
		t.Error("loadRig accepted a missing rig directory")
	}
}
