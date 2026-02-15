// SPDX-License-Identifier: MIT
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
		if report.TPM.QuoteSigSize > MaxSigSize {
			t.Fatal("parsed report has quote_sig_size exceeding max")
		}
		if report.TPM.AttestSize > MaxAttestSize {
			t.Fatal("parsed report has attest_size exceeding max")
		}
	})
}
