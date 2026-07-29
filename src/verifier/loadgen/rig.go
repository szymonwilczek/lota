// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Load Generator - Rig directory
//
// Rig directory is the persisted identity of a synthetic fleet:
// throwaway attestation CA, AIK key pool and generated verifier policy.
// Setup writes it once; every run reloads it, so the verifier under test keeps
// trusting the same CA and re-attesting clients keep their baselines across runs

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/szymonwilczek/lota/verifier/loadgen/synth"
)

const (
	rigCACertFile = "ca.crt"
	rigCAKeyFile  = "ca.key"
	rigKeysFile   = "aik-keys.pem"
	rigPolicyFile = "policy.yaml"
	rigMetaFile   = "rig.json"
)

// rigMeta records the setup-time shape so run can default to it
type rigMeta struct {
	Version int `json:"version"`
	Agents  int `json:"agents"`
	KeyPool int `json:"key_pool"`
}

// writeRig materializes new rig directory
func writeRig(dir string, agents, keyPool int) error {
	if keyPool <= 0 {
		keyPool = synth.DefaultKeyPool
	}
	keyPool = min(keyPool, agents)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create rig directory: %w", err)
	}

	ca, err := synth.NewCA()
	if err != nil {
		return err
	}
	keys, err := synth.GenerateKeyPool(keyPool)
	if err != nil {
		return err
	}
	// fleet only validates the profile and renders the policy here;
	// certificates are re-issued from the pool on every load
	fleet, err := synth.NewFleetWithKeys(ca, agents, keys)
	if err != nil {
		return err
	}
	policyYAML, err := fleet.PolicyYAML()
	if err != nil {
		return err
	}
	keysPEM, err := synth.KeyPoolPEM(keys)
	if err != nil {
		return err
	}
	meta, err := json.MarshalIndent(rigMeta{Version: 1, Agents: agents, KeyPool: keyPool}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal rig meta: %w", err)
	}

	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{rigCACertFile, ca.CertPEM(), 0o644},
		{rigCAKeyFile, ca.KeyPEM(), 0o600},
		{rigKeysFile, keysPEM, 0o600},
		{rigPolicyFile, policyYAML, 0o644},
		{rigMetaFile, append(meta, '\n'), 0o644},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
			return fmt.Errorf("write %s: %w", f.name, err)
		}
	}
	return nil
}

// loadRig rebuilds the fleet from rig directory
// agents <= 0 uses the setup-time fleet size
func loadRig(dir string, agents int) (*synth.Fleet, *rigMeta, error) {
	metaRaw, err := os.ReadFile(filepath.Join(dir, rigMetaFile))
	if err != nil {
		return nil, nil, fmt.Errorf("read rig meta (is %q a rig directory? run setup first): %w", dir, err)
	}
	var meta rigMeta
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", rigMetaFile, err)
	}
	if agents <= 0 {
		agents = meta.Agents
	}
	if agents > meta.Agents {
		return nil, nil, fmt.Errorf("requested %d agents but the rig was set up with %d; re-run setup",
			agents, meta.Agents)
	}

	certPEM, err := os.ReadFile(filepath.Join(dir, rigCACertFile))
	if err != nil {
		return nil, nil, fmt.Errorf("read rig CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, rigCAKeyFile))
	if err != nil {
		return nil, nil, fmt.Errorf("read rig CA key: %w", err)
	}
	ca, err := synth.LoadCA(certPEM, keyPEM)
	if err != nil {
		return nil, nil, err
	}

	keysPEM, err := os.ReadFile(filepath.Join(dir, rigKeysFile))
	if err != nil {
		return nil, nil, fmt.Errorf("read AIK key pool: %w", err)
	}
	keys, err := synth.LoadKeyPool(keysPEM)
	if err != nil {
		return nil, nil, err
	}

	fleet, err := synth.NewFleetWithKeys(ca, agents, keys)
	if err != nil {
		return nil, nil, err
	}
	return fleet, &meta, nil
}
