// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package main

import (
	"bytes"
	"debug/elf"
	"os"
	"path/filepath"
	"testing"
)

// TestComputeExpectedRuntimeMeasure_RealBinary measures the running test
// binary (a real ELF) and confirms the verifier-side parser succeeds and
// is deterministic on a genuine executable.
func TestComputeExpectedRuntimeMeasure_RealBinary(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	a, err := computeExpectedRuntimeMeasureSet([]string{self})
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	b, err := computeExpectedRuntimeMeasureSet([]string{self})
	if err != nil {
		t.Fatalf("measure (second): %v", err)
	}
	if a != b {
		t.Fatalf("non-deterministic: %x != %x", a, b)
	}
	var zero [32]byte
	if a == zero {
		t.Fatalf("measurement is all-zero")
	}
}

// TestComputeExpectedRuntimeMeasure_RejectsNonELF confirms the parser
// fails closed on a file that is not an ELF object.
func TestComputeExpectedRuntimeMeasure_RejectsNonELF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-elf.bin")
	if err := os.WriteFile(path, []byte("definitely not an ELF\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := computeExpectedRuntimeMeasureSet([]string{path}); err == nil {
		t.Fatalf("expected error on non-ELF input")
	}
}

// TestComputeExpectedRuntimeMeasure_RejectsMissing confirms a missing
// path returns an error rather than a silent zero measurement.
func TestComputeExpectedRuntimeMeasure_RejectsMissing(t *testing.T) {
	if _, err := computeExpectedRuntimeMeasureSet([]string{
		filepath.Join(t.TempDir(), "nope")}); err == nil {
		t.Fatalf("expected error on missing path")
	}
}

// TestRuntimeMeasureSet_OrderIndependent confirms the combined measure is
// independent of manifest order and that a multi-object set differs from
// a single-object measure of one member.
func TestRuntimeMeasureSet_OrderIndependent(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	// Two real ELF objects: the test binary and the dynamic loader,
	// which is always an executable ELF present on the host.
	loader := elfInterp(t, self)

	ab, err := computeExpectedRuntimeMeasureSet([]string{self, loader})
	if err != nil {
		t.Fatalf("set ab: %v", err)
	}
	ba, err := computeExpectedRuntimeMeasureSet([]string{loader, self})
	if err != nil {
		t.Fatalf("set ba: %v", err)
	}
	if ab != ba {
		t.Fatalf("order changed the combined digest")
	}
	one, err := computeExpectedRuntimeMeasureSet([]string{self})
	if err != nil {
		t.Fatalf("single: %v", err)
	}
	if ab == one {
		t.Fatalf("two-object set equals single-object measure")
	}
}

// TestRuntimeMeasureSet_Deterministic asserts the combined digest of a
// fixed set is stable across calls.
func TestRuntimeMeasureSet_Deterministic(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	set := []string{self, elfInterp(t, self)}
	a, err := computeExpectedRuntimeMeasureSet(set)
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	b, err := computeExpectedRuntimeMeasureSet(set)
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if a != b {
		t.Fatalf("non-deterministic combined digest")
	}
}

// elfInterp returns the program interpreter (dynamic loader) path of an
// ELF binary, a stable second real object for set tests.
func elfInterp(t *testing.T, path string) string {
	t.Helper()
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			buf := make([]byte, p.Filesz)
			if _, err := p.ReadAt(buf, 0); err != nil {
				t.Fatalf("read interp: %v", err)
			}
			return string(bytes.TrimRight(buf, "\x00"))
		}
	}
	t.Skip("no PT_INTERP (static binary); set test needs a second object")
	return ""
}
