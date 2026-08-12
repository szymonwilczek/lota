// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
//
// # Cross-language attestation-report layout test, Go half
//
// Parses the report written by report_gen.c with the production parser and checks
// every field against the position-derived patterns the C side wrote.
// Field added, removed or reordered on either side shifts the payload and fails here
// by name, in the build, instead of surfacing on real host as signature or PCR-digest
// error that says nothing about the layout.
//
// Patterns are restated here rather than shared:
// two independent statements of the same wire contract is the point of the test.
package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/szymonwilczek/lota/verifier/types"
)

const reportPath = "/tmp/lota_cross_report.bin"

const eventLog = "LOTA-CROSS-LANG-EVENT-LOG"

// pattern rebuilds the C side's (base ^ index) fill for field of size n
func pattern(base byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = base ^ byte(i)
	}
	return out
}

func main() {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "report_verify: cannot read %s: %v\n", reportPath, err)
		fmt.Fprintf(os.Stderr, "report_verify: run build/test_cross_lang_report_gen first\n")
		os.Exit(1)
	}

	report, err := types.ParseReport(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "report_verify: ParseReport failed: %v\n", err)
		os.Exit(1)
	}

	failures := 0
	fail := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "report_verify: FAIL "+format+"\n", args...)
		failures++
	}

	// header
	if report.Header.Magic != types.ReportMagic {
		fail("magic = %#08x, want %#08x", report.Header.Magic, types.ReportMagic)
	}
	if report.Header.Version != types.ReportVersion {
		fail("version = %#08x, want %#08x (C and Go disagree on the wire version)",
			report.Header.Version, types.ReportVersion)
	}
	if report.Header.ReportSize != uint32(len(data)) {
		fail("report_size = %d, file is %d bytes", report.Header.ReportSize, len(data))
	}
	if report.Header.Flags != 0xA5A5A5A5 {
		fail("flags = %#08x, want 0xa5a5a5a5", report.Header.Flags)
	}

	// TPM evidence
	for i := range types.PCRCount {
		want := pattern(byte(i), types.HashSize)
		if !bytes.Equal(report.TPM.PCRValues[i][:], want) {
			fail("pcr_values[%d] = %x, want %x", i, report.TPM.PCRValues[i][:8], want[:8])
			break
		}
	}
	if report.TPM.PCRMask != 0x00004083 {
		fail("pcr_mask = %#08x, want 0x4083", report.TPM.PCRMask)
	}
	if !bytes.Equal(report.TPM.QuoteSignature[:], pattern(0x11, types.MaxSigSize)) {
		fail("quote_signature mismatch (first bytes %x)", report.TPM.QuoteSignature[:8])
	}
	if report.TPM.QuoteSigSize != 256 {
		fail("quote_sig_size = %d, want 256", report.TPM.QuoteSigSize)
	}
	if !bytes.Equal(report.TPM.AttestData[:], pattern(0x22, types.MaxAttestSize)) {
		fail("attest_data mismatch (first bytes %x)", report.TPM.AttestData[:8])
	}
	if report.TPM.AttestSize != 145 {
		fail("attest_size = %d, want 145", report.TPM.AttestSize)
	}
	if !bytes.Equal(report.TPM.AIKPublic[:], pattern(0x33, types.MaxAIKPubSize)) {
		fail("aik_public mismatch (first bytes %x)", report.TPM.AIKPublic[:8])
	}
	if report.TPM.AIKPublicSize != 294 {
		fail("aik_public_size = %d, want 294", report.TPM.AIKPublicSize)
	}
	if !bytes.Equal(report.TPM.AIKCertificate[:], pattern(0x44, types.MaxAIKCertSize)) {
		fail("aik_certificate mismatch (first bytes %x)", report.TPM.AIKCertificate[:8])
	}
	if report.TPM.AIKCertSize != 1000 {
		fail("aik_cert_size = %d, want 1000", report.TPM.AIKCertSize)
	}
	// report carries no EK certificate:
	// wire version 2 dropped the always-empty field
	// if 2 KiB hole came back, every field below would be off by 2050 bytes
	// and the checks would fail
	if !bytes.Equal(report.TPM.Nonce[:], pattern(0x55, types.NonceSize)) {
		fail("nonce = %x, want %x (a stale ek_certificate field would shift this)",
			report.TPM.Nonce[:8], pattern(0x55, 8))
	}
	if !bytes.Equal(report.TPM.HardwareID[:], pattern(0x66, types.HardwareIDSize)) {
		fail("hardware_id = %x, want %x", report.TPM.HardwareID[:8], pattern(0x66, 8))
	}
	if report.TPM.AIKGeneration != 0x0102030405060708 {
		fail("aik_generation = %#016x, want 0x0102030405060708", report.TPM.AIKGeneration)
	}
	if !bytes.Equal(report.TPM.PrevAIKPublic[:], pattern(0x77, types.MaxAIKPubSize)) {
		fail("prev_aik_public mismatch (first bytes %x)", report.TPM.PrevAIKPublic[:8])
	}
	if report.TPM.PrevAIKSize != 300 {
		fail("prev_aik_public_size = %d, want 300", report.TPM.PrevAIKSize)
	}
	if report.TPM.QuoteSigAlg != types.TPMAlgRSASSA {
		fail("quote_sig_alg = %#04x, want %#04x", report.TPM.QuoteSigAlg, types.TPMAlgRSASSA)
	}
	if report.TPM.QuoteSigHashAlg != types.TPMAlgSHA256 {
		fail("quote_sig_hash_alg = %#04x, want %#04x", report.TPM.QuoteSigHashAlg, types.TPMAlgSHA256)
	}

	// system measurement
	if !bytes.Equal(report.System.KernelHash[:], pattern(0x88, types.HashSize)) {
		fail("kernel_hash = %x, want %x", report.System.KernelHash[:8], pattern(0x88, 8))
	}
	if !bytes.Equal(report.System.AgentHash[:], pattern(0x99, types.HashSize)) {
		fail("agent_hash = %x, want %x", report.System.AgentHash[:8], pattern(0x99, 8))
	}
	if got := string(bytes.TrimRight(report.System.KernelPath[:], "\x00")); got != "/boot/vmlinuz-cross-lang" {
		fail("kernel_path = %q, want %q", got, "/boot/vmlinuz-cross-lang")
	}
	if report.System.IOMMU.Vendor != 0x8086 || report.System.IOMMU.Flags != 0x07 ||
		report.System.IOMMU.UnitCount != 2 {
		fail("iommu = {vendor:%#x flags:%#x units:%d}, want {0x8086 0x7 2}",
			report.System.IOMMU.Vendor, report.System.IOMMU.Flags,
			report.System.IOMMU.UnitCount)
	}
	if got := string(bytes.TrimRight(report.System.IOMMU.CmdlineParam[:], "\x00")); got != "intel_iommu=on" {
		fail("iommu cmdline = %q, want %q", got, "intel_iommu=on")
	}

	// BPF summary
	if report.BPF.TotalExecEvents != 0x11223344 {
		fail("bpf.total_exec_events = %#08x, want 0x11223344", report.BPF.TotalExecEvents)
	}
	if report.BPF.UniqueBinaries != 0x55667788 {
		fail("bpf.unique_binaries = %#08x, want 0x55667788", report.BPF.UniqueBinaries)
	}
	if report.BPF.FirstEventTS != 0x0011223344556677 {
		fail("bpf.first_event_ts = %#016x, want 0x0011223344556677", report.BPF.FirstEventTS)
	}
	if report.BPF.LastEventTS != 0x7766554433221100 {
		fail("bpf.last_event_ts = %#016x, want 0x7766554433221100", report.BPF.LastEventTS)
	}

	// variable sections
	if got := string(report.EventLog); got != eventLog {
		fail("event log = %q, want %q", got, eventLog)
	}

	// mandatory ESRT section
	if report.ESRT == nil {
		fail("ESRT section missing; the parser must require it")
	} else {
		if !report.ESRT.Present {
			fail("esrt.present = false, want true")
		}
		if report.ESRT.FWVersion != 785 {
			fail("esrt.fw_version = %d, want 785", report.ESRT.FWVersion)
		}
		if report.ESRT.LowestSupported != 700 {
			fail("esrt.lowest_supported = %d, want 700", report.ESRT.LowestSupported)
		}
		if !bytes.Equal(report.ESRT.FWClass[:], pattern(0xC0, 16)) {
			fail("esrt.fw_class = %x, want %x", report.ESRT.FWClass[:], pattern(0xC0, 16))
		}
	}

	// file's length must be exactly what the Go constants predict
	wantLen := types.FixedReportSize + 4 + 4 + len(eventLog) + types.ESRTWireSize
	if len(data) != wantLen {
		fail("report is %d bytes, Go constants predict %d (FixedReportSize=%d)",
			len(data), wantLen, types.FixedReportSize)
	}

	// report truncated before the ESRT section must be refused
	truncated := data[:len(data)-types.ESRTWireSize]
	if _, err := types.ParseReport(truncated); err == nil {
		fail("parser accepted a report with no ESRT section")
	}

	if failures > 0 {
		fmt.Fprintf(os.Stderr, "\nreport_verify: %d layout mismatch(es) between C and Go\n", failures)
		os.Exit(1)
	}

	fmt.Printf("[Go] parsed %d-byte report from C: every field at the expected offset\n", len(data))
	fmt.Printf("[Go] wire version %#08x, event log %d bytes, ESRT present, no EK certificate field\n",
		report.Header.Version, len(report.EventLog))
	fmt.Println("[Go] CROSS-LANGUAGE REPORT LAYOUT TEST PASSED")
}
