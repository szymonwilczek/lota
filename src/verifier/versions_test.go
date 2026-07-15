// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

func TestReportWireStringMatchesConstant(t *testing.T) {
	// 0x00010000 must render as 1.0.0
	// bump to the report wire must move this string so the operator doc
	// and --print-versions stay truthful
	if got, want := reportWireString(), "1.0.0"; got != want {
		t.Errorf("reportWireString() = %q, want %q (ReportVersion=%#08x)",
			got, want, types.ReportVersion)
	}
}

func TestWriteVersionsReportsTargets(t *testing.T) {
	var buf bytes.Buffer
	writeVersions(&buf)
	out := buf.String()

	for _, want := range []string{
		"attestation report wire:  " + reportWireString(),
		"postgres schema target:   " + itoa(store.PgTargetSchemaVersion()),
		"sqlite schema target:     " + itoa(store.SQLiteTargetSchemaVersion()),
		"minimum TLS:              1.3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("writeVersions output missing %q\ngot:\n%s", want, out)
		}
	}
}

// itoa avoids pulling strconv into the test just for positive int
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
