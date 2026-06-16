// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Re-anchor discriminator tests

package verify

import (
	"encoding/binary"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/szymonwilczek/lota/verifier/types"
)

// encodeUEFIVar builds a UEFI_VARIABLE_DATA payload (inverse of
// parseUEFIVariableData) for a PCR 7 EV_EFI_VARIABLE_DRIVER_CONFIG event
func encodeUEFIVar(name string, data []byte) []byte {
	buf := make([]byte, 16) // GUID (zeros)
	units := utf16.Encode([]rune(name))
	tmp := make([]byte, 8)
	binary.LittleEndian.PutUint64(tmp, uint64(len(units)))
	buf = append(buf, tmp...)
	binary.LittleEndian.PutUint64(tmp, uint64(len(data)))
	buf = append(buf, tmp...)
	for _, u := range units {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, u)
		buf = append(buf, b...)
	}
	return append(buf, data...)
}

type pcrVar struct {
	name string
	data []byte
}

func pcr7Log(vars []pcrVar) []byte {
	entries := make([]EventLogEntry, 0, len(vars))
	for _, v := range vars {
		entries = append(entries, EventLogEntry{
			PCRIndex:  7,
			EventType: EvEFIVariableDriverConfig,
			Digests:   map[uint16][]byte{AlgSHA256: make([]byte, 32)},
			EventData: encodeUEFIVar(v.name, v.data),
		})
	}
	return buildTestEventLog(entries)
}

func baseVars() []pcrVar {
	return []pcrVar{
		{"PK", []byte("pk")},
		{"KEK", []byte("kek")},
		{"db", []byte("db")},
		{"dbx", []byte("dbx0")},
		{"SecureBoot", []byte{1}},
	}
}

// clone returns baseVars with the named variable replaced
func varsWith(name string, data []byte) []pcrVar {
	out := baseVars()
	for i := range out {
		if out[i].name == name {
			out[i].data = data
		}
	}
	return out
}

func esrt(v uint32) *types.ESRTInfo { return &types.ESRTInfo{Present: true, FWVersion: v} }

// mustParse parses a synthetic event log for the table tests;
// fixtures are always well-formed, so a parse error is a test bug
func mustParse(b []byte) *ParsedEventLog {
	p, err := ParseEventLog(b)
	if err != nil {
		panic(err)
	}
	return p
}

func TestReanchorDecision(t *testing.T) {
	base := pcr7Log(baseVars())

	tests := []struct {
		name string
		in   ReanchorInputs
		want ReanchorVerdict
	}{
		{
			name: "dbx append + firmware forward = strong allow",
			in: ReanchorInputs{
				BaselineEventLog:    base,
				CurrentParsed:       mustParse(pcr7Log(varsWith("dbx", []byte("dbx0+more")))),
				BaselineESRTVersion: 700, CurrentESRT: esrt(785), ESRTCapable: true,
			},
			want: ReanchorAllow,
		},
		{
			name: "dbx append + firmware version unchanged = LFA",
			in: ReanchorInputs{
				BaselineEventLog:    base,
				CurrentParsed:       mustParse(pcr7Log(varsWith("dbx", []byte("dbx0+more")))),
				BaselineESRTVersion: 785, CurrentESRT: esrt(785), ESRTCapable: true,
			},
			want: ReanchorLFA,
		},
		{
			name: "no ESRT and never capable = LFA",
			in: ReanchorInputs{
				BaselineEventLog: base,
				CurrentParsed:    mustParse(pcr7Log(varsWith("dbx", []byte("dbx0+more")))),
				CurrentESRT:      nil, ESRTCapable: false,
			},
			want: ReanchorLFA,
		},
		{
			name: "ESRT disappeared after being capable = escalate",
			in: ReanchorInputs{
				BaselineEventLog: base,
				CurrentParsed:    mustParse(pcr7Log(varsWith("dbx", []byte("dbx0+more")))),
				CurrentESRT:      nil, ESRTCapable: true,
			},
			want: ReanchorEscalate,
		},
		{
			name: "db changed = escalate",
			in: ReanchorInputs{
				BaselineEventLog: base,
				CurrentParsed:    mustParse(pcr7Log(varsWith("db", []byte("db-new")))),
				CurrentESRT:      esrt(785),
			},
			want: ReanchorEscalate,
		},
		{
			name: "KEK changed = escalate",
			in: ReanchorInputs{
				BaselineEventLog: base,
				CurrentParsed:    mustParse(pcr7Log(varsWith("KEK", []byte("kek-new")))),
				CurrentESRT:      esrt(785),
			},
			want: ReanchorEscalate,
		},
		{
			name: "dbx shrank = escalate",
			in: ReanchorInputs{
				BaselineEventLog: base,
				CurrentParsed:    mustParse(pcr7Log(varsWith("dbx", []byte("db")))),
				CurrentESRT:      esrt(785),
			},
			want: ReanchorEscalate,
		},
		{
			name: "dbx non-append change = escalate",
			in: ReanchorInputs{
				BaselineEventLog: base,
				CurrentParsed:    mustParse(pcr7Log(varsWith("dbx", []byte("XXXX-different")))),
				CurrentESRT:      esrt(785),
			},
			want: ReanchorEscalate,
		},
		{
			name: "firmware rollback = escalate",
			in: ReanchorInputs{
				BaselineEventLog:    base,
				CurrentParsed:       mustParse(pcr7Log(varsWith("dbx", []byte("dbx0+more")))),
				BaselineESRTVersion: 785, CurrentESRT: esrt(700), ESRTCapable: true,
			},
			want: ReanchorEscalate,
		},
		{
			name: "Secure Boot disabled in current = escalate",
			in: ReanchorInputs{
				BaselineEventLog: base,
				CurrentParsed:    mustParse(pcr7Log(varsWith("SecureBoot", []byte{0}))),
				CurrentESRT:      esrt(785),
			},
			want: ReanchorEscalate,
		},
		{
			name: "no baseline event log = escalate (fail-closed)",
			in: ReanchorInputs{
				BaselineEventLog: nil,
				CurrentParsed:    mustParse(base),
				CurrentESRT:      esrt(785),
			},
			want: ReanchorEscalate,
		},
		{
			name: "strong but within rate limit = escalate",
			in: ReanchorInputs{
				BaselineEventLog:    base,
				CurrentParsed:       mustParse(pcr7Log(varsWith("dbx", []byte("dbx0+more")))),
				BaselineESRTVersion: 700, CurrentESRT: esrt(785), ESRTCapable: true,
				LastReanchorAt: time.Now().Add(-24 * time.Hour),
				Now:            time.Now(),
			},
			want: ReanchorEscalate,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := reanchorDecision(tc.in)
			if got != tc.want {
				t.Errorf("verdict = %v (%q), want %v", got, reason, tc.want)
			}
		})
	}
}

// TestReanchorDecision_FirmwareFloor pins the ESRT anti-rollback floor as a
// gate on the strong path.
// ESRT carries the vendor's LowestSupported version alongside the running FWVersion;
// forward-versus-baseline update whose FWVersion sits below that floor is firmware
// running below its own declared lowest-supported version, so it must not earn the
// automatic strong re-anchor.
// Floor of zero means the vendor declared none and does not constrain the decision.
func TestReanchorDecision_FirmwareFloor(t *testing.T) {
	base := pcr7Log(baseVars())
	current := mustParse(pcr7Log(varsWith("dbx", []byte("dbx0+more"))))

	// forward vs baseline (785 > 700) but below the vendor floor (785 < 900):
	// escalate to the operator instead of auto re-anchor on the strong path
	below := ReanchorInputs{
		BaselineEventLog:    base,
		CurrentParsed:       current,
		BaselineESRTVersion: 700,
		CurrentESRT:         &types.ESRTInfo{Present: true, FWVersion: 785, LowestSupported: 900},
		ESRTCapable:         true,
	}
	if got, reason := reanchorDecision(below); got != ReanchorEscalate {
		t.Errorf("below-floor forward update: verdict = %v (%q), want escalate",
			got, reason)
	}

	// at the floor the forward update stays the strong path
	atFloor := below
	atFloor.CurrentESRT = &types.ESRTInfo{Present: true, FWVersion: 785, LowestSupported: 785}
	if got, reason := reanchorDecision(atFloor); got != ReanchorAllow {
		t.Errorf("at-floor forward update: verdict = %v (%q), want allow", got, reason)
	}

	// vendor that reports no floor (0) does not constrain the forward update
	noFloor := below
	noFloor.CurrentESRT = &types.ESRTInfo{Present: true, FWVersion: 785, LowestSupported: 0}
	if got, reason := reanchorDecision(noFloor); got != ReanchorAllow {
		t.Errorf("no-floor forward update: verdict = %v (%q), want allow", got, reason)
	}
}
