// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Load Generator - Rig directory tests

package main

import (
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
