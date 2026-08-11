// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
package verify

import (
	"bytes"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

// one EV_IPL entry as GRUB writes them:
// a NUL-terminated path and the digest of the bytes it read
func iplEntry(pcr uint32, path string, digest byte) EventLogEntry {
	d := bytes.Repeat([]byte{digest}, types.HashSize)
	return EventLogEntry{
		PCRIndex:  pcr,
		EventType: EvIPL,
		Digests:   map[uint16][]byte{AlgSHA256: d},
		EventData: append([]byte(path), 0),
	}
}

// the PCR 9 measurements a Fedora GRUB host makes, in order.
// grubenvDigest is the only thing that changes between two boots of one kernel:
// GRUB writes that file at boot and systemd writes it again on success,
// so its content records boot history rather than boot content.
func grubBootLog(grubenvDigest byte) *ParsedEventLog {
	return &ParsedEventLog{
		AlgorithmList: []uint16{AlgSHA256},
		Entries: []EventLogEntry{
			iplEntry(9, "(hd0,gpt3)/EFI/FEDORA/grub.cfg", 0xa7),
			iplEntry(9, "(hd0,gpt4)/grub2/grub.cfg", 0x66),
			iplEntry(9, "(hd0,gpt4)/grub2/grubenv", grubenvDigest),
			iplEntry(9, "(hd0,gpt4)/loader/entries//x-7.1.8-200.fc44.x86_64.conf", 0x24),
			iplEntry(9, "(hd0,gpt4)/vmlinuz-7.1.8-200.fc44.x86_64", 0x5b),
			iplEntry(9, "(hd0,gpt4)/initramfs-7.1.8-200.fc44.x86_64.img", 0xa9),
		},
	}
}

// PCR 9 is an aggregate over everything GRUB read, and one of those things
// is grubenv.
// Two boots of the same kernel quote different PCR 9 values, which is what makes
// the register useless as a kernel identifier: the recorded hash changes when
// nothing about the kernel did.
//
// The kernel image has its own measurement in the same log, and that one is
// a per-file digest, so it is stable across the reboot.
func TestExtractKernelImageDigest_StableAcrossBootsOfOneKernel(t *testing.T) {
	first, err := ExtractKernelImageDigest(grubBootLog(0x51))
	if err != nil {
		t.Fatalf("first boot: %v", err)
	}
	second, err := ExtractKernelImageDigest(grubBootLog(0x2e))
	if err != nil {
		t.Fatalf("second boot: %v", err)
	}

	if !first.Found || !second.Found {
		t.Fatalf("kernel image measurement not found: %+v / %+v", first, second)
	}
	if !bytes.Equal(first.Digest, second.Digest) {
		t.Errorf("kernel image digest moved across a reboot that changed only grubenv:\n first=%x\nsecond=%x",
			first.Digest, second.Digest)
	}
	if first.Path != "(hd0,gpt4)/vmlinuz-7.1.8-200.fc44.x86_64" {
		t.Errorf("named the wrong measurement: %q", first.Path)
	}
}

// a host that measures no kernel image says so
func TestExtractKernelImageDigest_AbsentIsNotZero(t *testing.T) {
	log := &ParsedEventLog{
		AlgorithmList: []uint16{AlgSHA256},
		Entries: []EventLogEntry{
			iplEntry(9, "(hd0,gpt4)/grub2/grubenv", 0x51),
		},
	}

	got, err := ExtractKernelImageDigest(log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Found {
		t.Errorf("claimed a kernel image measurement from a log without one: %+v", got)
	}
}

// Two different kernel images in one log is a log the verifier cannot read
// a single answer out of, so it refuses.
func TestExtractKernelImageDigest_ConflictingImagesRefused(t *testing.T) {
	log := grubBootLog(0x51)
	log.Entries = append(log.Entries,
		iplEntry(9, "(hd0,gpt4)/vmlinuz-7.0.13-200.fc44.x86_64", 0xcc))

	if _, err := ExtractKernelImageDigest(log); err == nil {
		t.Error("accepted a log measuring two different kernel images")
	}
}
