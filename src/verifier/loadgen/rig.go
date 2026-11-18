// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Load Generator - Rig directory

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

type rigMeta struct {
	Version int    `json:"version"`
	Agents  int    `json:"agents"`
	KeyPool int    `json:"key_pool"`
	Tenant  string `json:"tenant,omitempty"`
}

func writeRig(dir string, agents, keyPool int, tenant string) error {
	if keyPool <= 0 {
		keyPool = synth.DefaultKeyPool
	}
	keyPool = min(keyPool, agents)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create rig directory: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open rig directory: %w", err)
	}
	err = d.Chmod(0o700)
	d.Close()
	if err != nil {
		return fmt.Errorf("chmod rig directory: %w", err)
	}

	ca, err := synth.NewCA()
	if err != nil {
		return err
	}
	keys, err := synth.GenerateKeyPool(keyPool)
	if err != nil {
		return err
	}
	// built for the policy only; loadRig issues the certificates again
	fleet, err := synth.NewFleet(ca, agents, keys, tenant)
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
	meta, err := json.MarshalIndent(rigMeta{Version: 1, Agents: agents, KeyPool: keyPool, Tenant: tenant}, "", "  ")
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
		path := filepath.Join(dir, f.name)
		if err := writeRigFile(path, f.data, f.mode); err != nil {
			return fmt.Errorf("write %s: %w", f.name, err)
		}
	}
	return nil
}

// writeRigFile writes data to a new file of mode and renames it onto path,
// so a descriptor still open on the old file never reads the new data.
func writeRigFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".rig-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	err = f.Chmod(mode)
	if err == nil {
		_, err = f.Write(data)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// loadRig rebuilds the fleet from dir. agents <= 0 means the setup size,
// and more than the setup size is an error.
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
	// LoadKeyPool skips a damaged block, so a short pool is a damaged one
	if len(keys) != meta.KeyPool {
		return nil, nil, fmt.Errorf("AIK key pool damaged: %d of %d "+
			"keys load; re-run setup", len(keys), meta.KeyPool)
	}

	fleet, err := synth.NewFleet(ca, agents, keys, meta.Tenant)
	if err != nil {
		return nil, nil, err
	}
	return fleet, &meta, nil
}
