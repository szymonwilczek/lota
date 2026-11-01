// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package ca

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// counts resolver dials until the returned restore runs
func countingDial(t *testing.T) (*atomic.Int64, func()) {
	t.Helper()
	var dials atomic.Int64

	resolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dials.Add(1)
			return resolver.Dial(ctx, network, address)
		},
	}
	return &dials, func() { net.DefaultResolver = resolver }
}

// The README says pinning an intermediate the device also presents is
// harmless: EK verification builds from pins and device certs, never dials.
func TestBundledIntermediateCostsNoEnrollmentFetch(t *testing.T) {
	pki := newFirmwarePKI(t)
	dials, restore := countingDial(t)
	defer restore()

	cases := []struct {
		name    string
		anchors []certAndKey
		path    []certAndKey
		supply  [][]byte
	}{
		{
			name:    "intermediate supplied by the device",
			anchors: []certAndKey{pki.root},
			path:    pki.published,
			supply:  pki.onChipDER(),
		},
		{
			name:    "intermediate pinned as well",
			anchors: []certAndKey{pki.root},
			path:    append(append([]certAndKey{}, pki.published...), pki.onChip...),
			supply:  pki.onChipDER(),
		},
		{
			name:    "pinned, and the device presents none",
			anchors: []certAndKey{pki.root},
			path:    append(append([]certAndKey{}, pki.published...), pki.onChip...),
			supply:  nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			is := pki.issuer(t, tc.anchors, tc.path)
			if _, err := is.VerifyEKCertificate(pki.ekDER, tc.supply, time.Now()); err != nil {
				t.Fatalf("EK refused: %v", err)
			}
		})
	}

	if n := dials.Load(); n != 0 {
		t.Errorf("EK verification dialed %d times; the path holds no outbound connection", n)
	}
}
