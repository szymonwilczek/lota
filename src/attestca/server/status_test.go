// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// What the CA tells a device when it refuses to enrol it.
//
// The status is the only part of a refusal the device sees, and it decides
// whether the device tries again: an internal error is transient by definition,
// while a policy refusal will be refused forever. Every refusal the CA makes
// on purpose therefore has to carry a status that says so, and StatusInternalError
// has to keep meaning "the CA faulted" or it cannot be alerted on.

package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/szymonwilczek/lota/attestca/ca"
	"github.com/szymonwilczek/lota/attestca/credential"
	"github.com/szymonwilczek/lota/attestca/enroll"
	"github.com/szymonwilczek/lota/attestca/internal/tpmtest"
	"github.com/szymonwilczek/lota/attestca/wire"
	"github.com/szymonwilczek/lota/crl"
)

// A strict tenant manifest that names one EK and not the other
func newSvcStrictManifest(t *testing.T) (*enroll.Service, tpmtest.Root) {
	t.Helper()
	root := tpmtest.NewVendorRoot(t, "tpm-vendor-root")
	listed := tpmtest.NewEKCert(t, root)

	path := filepath.Join(t.TempDir(), "tenants")
	line := enroll.EKFingerprint(&listed.Priv.PublicKey) + " acme\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	manifest, err := enroll.LoadTenantManifest(path, true)
	if err != nil {
		t.Fatalf("LoadTenantManifest: %v", err)
	}

	caCertPEM, caKeyPEM := tpmtest.LOTACAPEM(t)
	issuer, err := ca.NewIssuer(ca.IssuerConfig{
		CACertPEM:  caCertPEM,
		CAKeyPEM:   caKeyPEM,
		EKRootPEMs: [][]byte{tpmtest.PEM("CERTIFICATE", root.DER)},
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	svc, err := enroll.NewService(issuer, []byte("pseudonym-key-0123456789abcdef"),
		enroll.WithTenantManifest(manifest))
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	return svc, root
}

// The refusal an operator configures on purpose: this machine was never added
// to the manifest. It is the EK that was refused, and no retry will change it.
func TestServerRejectsUnlistedEKAsEKRejected(t *testing.T) {
	svc, root := newSvcStrictManifest(t)
	addr, pool, stop := startServer(t, svc)
	defer stop()

	unlisted := tpmtest.NewEKCert(t, root)
	challenge, result := enrollClient(t, addr, pool, unlisted, nil, nil)
	if result != nil {
		t.Fatalf("expected rejection at challenge, got result %+v", result)
	}
	if challenge.Status == wire.StatusInternalError {
		t.Fatal("an unlisted EK is reported as an internal CA error, which means retry")
	}
	if challenge.Status != wire.StatusEKRejected {
		t.Fatalf("status %d, want StatusEKRejected", challenge.Status)
	}
}

// The default arm of the classifier is for faults.
// Every refusal the CA makes on purpose is listed here, so a new one cannot be
// added without deciding what the device is told.
func TestBeginStatusClassifiesEveryDeliberateRefusal(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want uint16
	}{
		{
			name: "unlisted EK under a strict tenant manifest",
			err:  fmt.Errorf("tenant assignment: %w", enroll.ErrEKNotListed),
			want: wire.StatusEKRejected,
		},
		{
			name: "EK revoked by the manufacturer feed",
			err: fmt.Errorf("EK verification: %w",
				fmt.Errorf("EK certificate revocation: %w", crl.ErrCertificateRevoked)),
			want: wire.StatusEKRejected,
		},
		{
			name: "EK whose modulus carries the ROCA fingerprint",
			err:  fmt.Errorf("EK verification: %w", ca.ErrEKWeakKey),
			want: wire.StatusEKRejected,
		},
		{
			name: "EK that does not chain to a pinned root",
			err:  fmt.Errorf("EK verification: %w", ca.ErrEKChain),
			want: wire.StatusEKRejected,
		},
		{
			name: "AIK template that is not a restricted signing key",
			err:  fmt.Errorf("AIK validation: %w", credential.ErrAIKTemplate),
			want: wire.StatusAIKRejected,
		},
		{
			name: "enrollment token the CA does not know",
			err:  fmt.Errorf("tenant assignment: %w", enroll.ErrTokenUnknown),
			want: wire.StatusTokenRejected,
		},
		{
			name: "more pending sessions than the CA holds",
			err:  enroll.ErrTooManyPending,
			want: wire.StatusRateLimited,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := beginStatus(tc.err); got != tc.want {
				t.Fatalf("status %d, want %d (%v)", got, tc.want, tc.err)
			}
		})
	}
}

// arm keeps its meaning: something the CA cannot serve, which a device may retry
func TestBeginStatusKeepsInternalErrorForFaults(t *testing.T) {
	if got := beginStatus(errors.New("write pseudonym key: disk full")); got != wire.StatusInternalError {
		t.Fatalf("status %d for a CA fault, want StatusInternalError", got)
	}
}
