// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package ca

import (
	"context"
	"net"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// outside the module, so not in the test cache key: run with -count=1
const ekRootsReadme = "../../../configs/ek-roots/README.rst"

func readEKRootsReadme(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(ekRootsReadme)
	if err != nil {
		t.Fatalf("read %s: %v", ekRootsReadme, err)
	}
	return string(data)
}

// sentences with line wraps collapsed, so a claim matches across lines
func sentencesOf(text string) []string {
	flat := strings.Join(strings.Fields(text), " ")
	var out []string
	for s := range strings.SplitSeq(flat, ". ") {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

var (
	fetchWord   = regexp.MustCompile(`(?i)\bfetch(es|ed|ing)?\b|\bdownload(s|ed|ing)?\b`)
	enrollWord  = regexp.MustCompile(`(?i)\benroll(ment|s|ing)?\b`)
	negation    = regexp.MustCompile(`(?i)\b(no|nothing|never|not|without)\b`)
	buildTimeIt = regexp.MustCompile(`(?i)lota-ek-root-pin\.sh|bundle is (built|assembled)|when the bundle is`)
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

// The only fetch is lota-ek-root-pin.sh's AIA walk when the bundle is built;
// none happens at enrollment.
func TestBundleReadmePutsTheSavedFetchWhereItHappens(t *testing.T) {
	text := readEKRootsReadme(t)

	for _, s := range sentencesOf(text) {
		if !fetchWord.MatchString(s) || !enrollWord.MatchString(s) {
			continue
		}
		if !negation.MatchString(s) {
			t.Errorf("a sentence puts a fetch at enrollment time: %q", s)
		}
	}

	var found bool
	for _, s := range sentencesOf(text) {
		if fetchWord.MatchString(s) && buildTimeIt.MatchString(s) {
			found = true
			break
		}
	}
	if !found {
		t.Error("no sentence puts the fetch where it happens: the pin script's AIA walk, when the bundle is built")
	}
}
