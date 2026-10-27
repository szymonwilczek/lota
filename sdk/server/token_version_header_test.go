// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package server

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// outside the module, so not in the test cache key: run with -count=1
var tokenVersionHeaders = []string{
	"lota_token.h",
	"lota_ipc.h",
	"lota_gaming.h",
}

// "0/1 = PID set", "2 = + image": versions left of an "="
var namedVersions = regexp.MustCompile(`([0-9]+(?:/[0-9]+)*)\s*=[^=]`)

// probes ParseToken with the field overwritten in a valid token
func acceptedRuntimeProtectVersions(t *testing.T) []int {
	t.Helper()

	priv := generateTestKey(t)
	var nonce [32]byte
	pcrDigest := make([]byte, 32)
	tok := buildTestToken(t, priv, uint64(time.Now().Add(time.Hour).Unix()),
		0, nonce, 0x00000001, pcrDigest)

	var accepted []int
	for v := 0; v <= 4; v++ {
		probe := make([]byte, len(tok))
		copy(probe, tok)
		binary.LittleEndian.PutUint16(probe[142:144], uint16(v))
		if _, err := ParseToken(probe); err == nil {
			accepted = append(accepted, v)
		}
	}
	return accepted
}

// runtime_protect_version annotations by line; an unclosed parenthesis
// continues onto the next line, as in the wire-layout table
func versionAnnotations(t *testing.T, path string) map[int]string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	lines := strings.Split(string(data), "\n")

	out := make(map[int]string)
	for i, line := range lines {
		_, note, found := strings.Cut(line, "runtime_protect_version")
		if !found {
			continue
		}
		if strings.Count(note, "(") > strings.Count(note, ")") && i+1 < len(lines) {
			note += " " + strings.TrimLeft(lines[i+1], " \t*")
		}
		if namedVersions.MatchString(note) {
			out[i+1] = note
		}
	}
	return out
}

func versionsNamedIn(note string) []int {
	seen := make(map[int]bool)
	for _, m := range namedVersions.FindAllStringSubmatch(note, -1) {
		for field := range strings.SplitSeq(m[1], "/") {
			n, err := strconv.Atoi(field)
			if err != nil {
				continue
			}
			seen[n] = true
		}
	}
	var out []int
	for n := range seen {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

func sameVersions(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func show(v []int) string {
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = fmt.Sprint(n)
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// A reimplementer follows the installed headers; a version no parser takes
// yields tokens every verifier refuses.
func TestHeaderAnnotationsNameTheVersionsParsersAccept(t *testing.T) {
	accepted := acceptedRuntimeProtectVersions(t)
	if !sameVersions(accepted, []int{1, 2}) {
		t.Fatalf("ParseToken accepts %s, expected the two defined versions", show(accepted))
	}

	checked := 0
	for _, name := range tokenVersionHeaders {
		path := filepath.Join("..", "..", "include", name)
		notes := versionAnnotations(t, path)
		if len(notes) == 0 {
			t.Errorf("%s: no annotation of runtime_protect_version names a version", name)
			continue
		}
		for line, note := range notes {
			named := versionsNamedIn(note)
			if !sameVersions(named, accepted) {
				t.Errorf("include/%s:%d names versions %s, parsers accept %s: %s",
					name, line, show(named), show(accepted), strings.TrimSpace(note))
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no version annotation found in any header")
	}
	t.Logf("%d annotations checked against %s", checked, show(accepted))
}
