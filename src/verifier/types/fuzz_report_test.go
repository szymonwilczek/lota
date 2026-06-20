// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Fuzz tests for binary report parser

package types

import (
	"encoding/binary"
	"testing"
)

func FuzzParseReport(f *testing.F) {
	// seed: minimal valid report from unit tests
	seed := createTestReportBytes()
	f.Add(seed)

	// seed: minimal report with event log appended
	withLog := make([]byte, len(seed))
	copy(withLog, seed)
	eventCountBuf := make([]byte, 4)
	withLog = append(withLog, eventCountBuf...) // event_count=0 already in seed
	eventLogSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(eventLogSize, 5)
	withLog = append(withLog, eventLogSize...)
	withLog = append(withLog, []byte("hello")...)
	binary.LittleEndian.PutUint32(withLog[24:28], uint32(len(withLog)))
	f.Add(withLog)

	// seed: just the header (too short, should be rejected)
	f.Add(seed[:32])

	f.Fuzz(func(t *testing.T, data []byte) {
		report, err := ParseReport(data)
		if err != nil {
			if report != nil {
				t.Fatal("ParseReport returned non-nil report with error")
			}
			return
		}
		if report == nil {
			t.Fatal("ParseReport returned nil without error")
		}
		if report.Header.Magic != ReportMagic {
			t.Fatal("parsed report has wrong magic")
		}
		if report.Header.Version != ReportVersion {
			t.Fatal("parsed report has wrong version")
		}
		// every variable-length field's declared size must fit its fixed buffer
		// size past the buffer is the exact bug that lets a later consumer slice
		// out of bounds, so the parser must never accept one
		if report.TPM.QuoteSigSize > MaxSigSize {
			t.Fatalf("quote_sig_size %d exceeds max %d", report.TPM.QuoteSigSize, MaxSigSize)
		}
		if report.TPM.AttestSize > MaxAttestSize {
			t.Fatalf("attest_size %d exceeds max %d", report.TPM.AttestSize, MaxAttestSize)
		}
		if report.TPM.AIKPublicSize > MaxAIKPubSize {
			t.Fatalf("aik_public_size %d exceeds max %d", report.TPM.AIKPublicSize, MaxAIKPubSize)
		}
		if report.TPM.AIKCertSize > MaxAIKCertSize {
			t.Fatalf("aik_cert_size %d exceeds max %d", report.TPM.AIKCertSize, MaxAIKCertSize)
		}
		if report.TPM.EKCertSize > MaxEKCertSize {
			t.Fatalf("ek_cert_size %d exceeds max %d", report.TPM.EKCertSize, MaxEKCertSize)
		}
		if report.TPM.PrevAIKSize > MaxAIKPubSize {
			t.Fatalf("prev_aik_size %d exceeds max %d", report.TPM.PrevAIKSize, MaxAIKPubSize)
		}
		// determinism:
		// re-parsing the same bytes must reach the same verdict
		// and yield the same declared report size
		again, err2 := ParseReport(data)
		if err2 != nil || again == nil {
			t.Fatal("ParseReport nondeterministic: second parse failed")
		}
		if again.Header.ReportSize != report.Header.ReportSize {
			t.Fatalf("ParseReport nondeterministic: report_size %d then %d",
				report.Header.ReportSize, again.Header.ReportSize)
		}
	})
}
