// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package server

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// Shipped Prometheus config; each job's transport must match the bind:
// loopback is plain HTTP without a key, anything else is TLS plus reader key.
// A mismatch fails silently, the target just shows as down.
const referenceScrapeConfig = "../../../deploy/observability/prometheus.yml"

type scrapeConfigFile struct {
	ScrapeConfigs []struct {
		JobName   string `yaml:"job_name"`
		Scheme    string `yaml:"scheme"`
		TLSConfig struct {
			CAFile string `yaml:"ca_file"`
		} `yaml:"tls_config"`
		Authorization struct {
			CredentialsFile string `yaml:"credentials_file"`
		} `yaml:"authorization"`
		StaticConfigs []struct {
			Targets []string `yaml:"targets"`
		} `yaml:"static_configs"`
	} `yaml:"scrape_configs"`
}

func loadReferenceScrapeConfig(t *testing.T) scrapeConfigFile {
	t.Helper()

	raw, err := os.ReadFile(filepath.Clean(referenceScrapeConfig))
	if err != nil {
		t.Fatalf("read %s: %v", referenceScrapeConfig, err)
	}
	var cfg scrapeConfigFile
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parse %s: %v", referenceScrapeConfig, err)
	}
	if len(cfg.ScrapeConfigs) == 0 {
		t.Fatalf("%s has no scrape job at all", referenceScrapeConfig)
	}
	return cfg
}

// Uses isLoopbackAddr, same as the bind, so config and listener cannot drift.
func TestReferenceScrapeConfigMatchesTheTransportTheBindServes(t *testing.T) {
	cfg := loadReferenceScrapeConfig(t)

	for _, job := range cfg.ScrapeConfigs {
		for _, sc := range job.StaticConfigs {
			for _, target := range sc.Targets {
				if isLoopbackAddr(target) {
					if job.Scheme != "http" {
						t.Errorf("job %q scrapes loopback target %s over %q; the loopback bind is plain HTTP",
							job.JobName, target, job.Scheme)
					}
					continue
				}
				if job.Scheme != "https" {
					t.Errorf("job %q scrapes %s over %q; a non-loopback bind is served with TLS",
						job.JobName, target, job.Scheme)
				}
				if job.TLSConfig.CAFile == "" {
					t.Errorf("job %q scrapes %s over TLS without naming the CA that issued the verifier's certificate",
						job.JobName, target)
				}
				if job.Authorization.CredentialsFile == "" {
					t.Errorf("job %q scrapes %s without a reader key; that bind refuses to start without one",
						job.JobName, target)
				}
			}
		}
	}
}

// The config must ship a non-loopback job for a remote monitoring host.
func TestReferenceScrapeConfigCoversTheDeploymentItIsWrittenFor(t *testing.T) {
	cfg := loadReferenceScrapeConfig(t)

	for _, job := range cfg.ScrapeConfigs {
		for _, sc := range job.StaticConfigs {
			for _, target := range sc.Targets {
				if !isLoopbackAddr(target) {
					return
				}
			}
		}
	}

	t.Fatalf("%s only configures loopback targets; a separate monitoring host has no job to start from",
		referenceScrapeConfig)
}
