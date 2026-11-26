// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Re-anchor discriminator tests

package verify

import (
	"bytes"
	"encoding/binary"
	"log/slog"
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
		entries = append(entries, measuredEntry(7, EvEFIVariableDriverConfig,
			encodeUEFIVar(v.name, v.data)))
	}
	return buildTestEventLog(append(entries, separatorEntry()))
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

func TestPCR7Variables_AfterSeparator(t *testing.T) {
	entries := []EventLogEntry{
		measuredEntry(7, EvEFIVariableDriverConfig, encodeUEFIVar("db", []byte("db"))),
		separatorEntry(),
		measuredEntry(7, EvEFIVariableDriverConfig, encodeUEFIVar("db", []byte("root"))),
	}
	got := pcr7Variables(&ParsedEventLog{Entries: entries})
	if string(got["db"]) != "db" {
		t.Errorf("db read from after the separator: %q", got["db"])
	}

	offDigest := entries[0]
	offDigest.EventData = encodeUEFIVar("db", []byte("root"))
	got = pcr7Variables(&ParsedEventLog{Entries: []EventLogEntry{offDigest, separatorEntry()}})
	if _, ok := got["db"]; ok {
		t.Errorf("db read off its digest: %q", got["db"])
	}
}

func TestReanchorDecision(t *testing.T) {
	base := pcr7Log(baseVars())
	withDBT := pcr7Log(append(baseVars(), pcrVar{"dbt", []byte("t")}))
	withDBR := pcr7Log(append(baseVars(), pcrVar{"dbr", []byte("t")}))

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
			name: "ESRT first appears = LFA",
			in: ReanchorInputs{
				BaselineEventLog: base,
				CurrentParsed:    mustParse(base),
				CurrentESRT:      esrt(785), ESRTCapable: false,
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
			name: "PCR 7 variable renamed = escalate",
			in: ReanchorInputs{
				BaselineEventLog:    withDBT,
				CurrentParsed:       mustParse(withDBR),
				BaselineESRTVersion: 700,
				CurrentESRT:         esrt(785),
				ESRTCapable:         true,
			},
			want: ReanchorEscalate,
		},
		{
			name: "same PCR 7 names + firmware forward = allow",
			in: ReanchorInputs{
				BaselineEventLog:    withDBT,
				CurrentParsed:       mustParse(withDBT),
				BaselineESRTVersion: 700,
				CurrentESRT:         esrt(785),
				ESRTCapable:         true,
			},
			want: ReanchorAllow,
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

// TestReanchorDecision_FirmwareFloorUnchangedVersion pins the anti-rollback
// floor on the unchanged-version (LFA) path too, not only the forward/strong
// path.
// Firmware reporting that it runs below its own declared LowestSupported is
// the rollback the floor exists to catch regardless of how the version compares
// to the baseline, so an unchanged-version drift report below the floor must escalate.
func TestReanchorDecision_FirmwareFloorUnchangedVersion(t *testing.T) {
	const floorReason = "firmware version below vendor anti-rollback floor"
	base := pcr7Log(baseVars())
	current := mustParse(pcr7Log(varsWith("dbx", []byte("dbx0+more"))))

	// unchanged version vs baseline (700 == 700),
	// normally the LFA path, but the firmware reports
	// running below the vendor floor (700 < 900)
	below := ReanchorInputs{
		BaselineEventLog:    base,
		CurrentParsed:       current,
		BaselineESRTVersion: 700,
		CurrentESRT:         &types.ESRTInfo{Present: true, FWVersion: 700, LowestSupported: 900},
		ESRTCapable:         true,
	}
	if got, reason := reanchorDecision(below); got != ReanchorEscalate || reason != floorReason {
		t.Errorf("below-floor unchanged version: verdict = %v (%q), want escalate (%q)",
			got, reason, floorReason)
	}

	// at the floor the unchanged version must not trip the floor escalation
	atFloor := below
	atFloor.CurrentESRT = &types.ESRTInfo{Present: true, FWVersion: 700, LowestSupported: 700}
	if _, reason := reanchorDecision(atFloor); reason == floorReason {
		t.Errorf("at-floor unchanged version must not trip the anti-rollback floor")
	}
}

const evPlatformConfigFlags uint32 = 0x0000000A

func bootVar(name string, data []byte) EventLogEntry {
	return measuredEntry(1, EvEFIVariableBoot,
		encodeUEFIVariableData(efiGlobalVariableGUID, name, data))
}

// a boot whose PCR 1 carries the platform flags and the given boot variables
func bootEntryLog(crtm string, sb byte, flags string,
	vars ...EventLogEntry,
) []byte {
	sbVar := encodeUEFIVariableData(efiGlobalVariableGUID, "SecureBoot",
		[]byte{sb})
	entries := []EventLogEntry{
		measuredEntry(0, 0x00000008, []byte(crtm)),
		measuredEntry(7, EvEFIVariableDriverConfig, sbVar),
		separatorEntry(),
		measuredEntry(1, evPlatformConfigFlags, []byte(flags)),
	}
	entries = append(entries, vars...)
	entries = append(entries,
		measuredEntry(1, EvSeparator, make([]byte, 4)))
	return buildTestEventLog(entries)
}

var (
	pinnedOrder = []byte{1, 0, 0, 0}
	movedOrder  = []byte{0, 1, 0, 0}
)

// the pinned boot's entries, BootOrder replaced by order
func bootEntries(order []byte) []EventLogEntry {
	return []EventLogEntry{
		bootVar("BootOrder", order),
		bootVar("Boot0000", []byte("linux")),
		bootVar("Boot0001", []byte("usb")),
	}
}

func pinnedBootEntries() []EventLogEntry { return bootEntries(pinnedOrder) }

// the pinned boot's entries and one more
func addedBootEntry() []EventLogEntry {
	return append(pinnedBootEntries(),
		bootVar("Boot0002", []byte("windows")))
}

func TestBootEntryPCR1Change(t *testing.T) {
	pinned := mustParse(bootEntryLog("crtm", 1, "flags",
		pinnedBootEntries()...))

	offDigest := bootEntries(movedOrder)
	offDigest[0].EventData = encodeUEFIVariableData(efiGlobalVariableGUID,
		"BootOrder", pinnedOrder)
	boot2 := bootEntries(movedOrder)
	boot2[0].EventType = EvEFIVariableBoot2
	vendor := append(pinnedBootEntries(),
		measuredEntry(1, EvEFIVariableBoot, encodeUEFIVariableData(
			[16]byte{1}, "BootOrder", movedOrder)))
	badName := append(pinnedBootEntries(), bootVar("Boot000x", []byte("x")))

	tests := []struct {
		name    string
		flags   string
		current []EventLogEntry
		ok      bool
	}{
		{"boot order", "flags", bootEntries(movedOrder), true},
		{"entry added", "flags", addedBootEntry(), true},
		{"boot2 event", "flags", boot2, true},
		{"nothing moved", "flags", pinnedBootEntries(), false},
		{"flags moved", "other", bootEntries(movedOrder), false},
		{"data off its digest", "flags", offDigest, false},
		{"vendor namespace", "flags", vendor, false},
		{"not a boot entry name", "flags", badName, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			current := mustParse(bootEntryLog("crtm", 1, tt.flags,
				tt.current...))
			err := bootEntryPCR1Change(pinned, current)
			if (err == nil) != tt.ok {
				t.Fatalf("got %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

type bootEntryCase struct {
	v      *Verifier
	id     string
	pinned BootBaseline
	boot   BootBaseline
	report *types.AttestationReport
	facts  *BootFacts
}

func bootOfLog(t *testing.T, log []byte) BootBaseline {
	t.Helper()
	replay, err := ReplayEventLog(mustParse(log))
	if err != nil {
		t.Fatal(err)
	}
	return BootBaseline{PCR0: replay.PCRValues[0],
		PCR1: replay.PCRValues[1], PCR7: replay.PCRValues[7]}
}

// bootWith moves the case to a report of log
func (c *bootEntryCase) bootWith(t *testing.T, log []byte) {
	t.Helper()
	c.boot = bootOfLog(t, log)
	c.report = &types.AttestationReport{EventLog: log}
	c.facts = &BootFacts{Parsed: mustParse(log), SecureBootTrusted: true,
		SecureBoot: SecureBootState{Found: true, Enabled: true}}
}

// a client that spent its LFA re-anchor on the pinned boot and boots current
func newBootEntryCase(t *testing.T, current []byte) *bootEntryCase {
	t.Helper()

	v := NewVerifier(DefaultConfig(), newCertVerifier(t))
	policy := DefaultPolicy()
	policy.Profile = ProfileConsumer
	policy.RequireSecureBoot = true
	if err := v.AddPolicy(policy); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	pinnedLog := bootEntryLog("crtm", 1, "flags", pinnedBootEntries()...)
	c := &bootEntryCase{v: v, id: "boot-entry-client",
		pinned: bootOfLog(t, pinnedLog)}
	v.baselineStore.(AtomicBaselineStorer).CheckAndUpdateAttestation(c.id,
		[types.HashSize]byte{1}, fixtureAgentHash(), &c.pinned, false)
	rs := v.baselineStore.(ReanchorStorer)
	if err := rs.ArchiveAndReanchor(c.id, c.pinned, pinnedLog, 0, false,
		true, "lfa", time.Now()); err != nil {
		t.Fatal(err)
	}
	c.bootWith(t, current)
	return c
}

func (c *bootEntryCase) try() bool {
	return c.v.tryReanchor(slog.Default(), c.id, "", &c.pinned, &c.boot,
		c.report, c.facts)
}

func (c *bootEntryCase) pinnedNow(t *testing.T) BootBaseline {
	t.Helper()
	r := c.v.baselineStore.(BootBaselineReader)
	b, err := r.GetBootBaseline(c.id)
	if err != nil || b == nil {
		t.Fatalf("GetBootBaseline: %v, %v", b, err)
	}
	return BootBaseline{PCR0: b.PCR0, PCR1: b.PCR1, PCR7: b.PCR7}
}

// inside the LFA interval a boot entry change still re-pins, and spends nothing
func TestTryReanchor_BootEntriesRepinPCR1(t *testing.T) {
	current := bootEntryLog("crtm", 1, "flags", addedBootEntry()...)
	c := newBootEntryCase(t, current)
	rs := c.v.baselineStore.(ReanchorStorer)
	before := rs.GetReanchorState(c.id)

	if !c.try() {
		t.Fatal("a boot entry change must re-pin PCR 1")
	}
	if got := c.pinnedNow(t); got != c.boot {
		t.Fatalf("pin %x, want %x", got.PCR1, c.boot.PCR1)
	}
	st := rs.GetReanchorState(c.id)
	if !bytes.Equal(st.EventLogBaseline, current) {
		t.Fatal("boot evidence did not move with the pin")
	}
	if st.ReanchorCount != before.ReanchorCount ||
		!st.LastReanchorAt.Equal(before.LastReanchorAt) {
		t.Fatal("the boot entry re-pin spent the re-anchor limit")
	}

	c.pinned = c.boot
	c.bootWith(t, bootEntryLog("crtm", 1, "flags", pinnedBootEntries()...))
	if !c.try() {
		t.Fatal("a second boot entry change must re-pin too")
	}
}

// anything beyond the boot entries takes the firmware road, which the spent
// LFA interval refuses
func TestTryReanchor_BootEntriesRefusals(t *testing.T) {
	offPin := func(c *bootEntryCase) {
		_ = c.v.baselineStore.(ReanchorStorer).RecordBootEvidence(c.id,
			bootEntryLog("crtm", 1, "flags"), 0, false)
	}
	tests := []struct {
		name   string
		crtm   string
		sb     byte
		flags  string
		mutate func(*bootEntryCase)
	}{
		{"platform flags moved", "crtm", 1, "other", nil},
		{"PCR 0 moved", "crtm2", 1, "flags", nil},
		{"PCR 7 moved", "crtm", 2, "flags", nil},
		{"log off the pin", "crtm", 1, "flags", offPin},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newBootEntryCase(t, bootEntryLog(tt.crtm, tt.sb,
				tt.flags, addedBootEntry()...))
			if tt.mutate != nil {
				tt.mutate(c)
			}
			if c.try() {
				t.Fatal("re-pinned")
			}
			if c.pinnedNow(t) != c.pinned {
				t.Fatal("refusal moved the pin")
			}
		})
	}
}

// the row moved after the decision read it: the write refuses
func TestTryReanchor_BootEntriesRaceRefused(t *testing.T) {
	c := newBootEntryCase(t, bootEntryLog("crtm", 1, "flags",
		addedBootEntry()...))
	other := c.pinned
	other.PCR1[0] ^= 1
	rs := c.v.baselineStore.(ReanchorStorer)
	pinnedLog := rs.GetReanchorState(c.id).EventLogBaseline
	bs := c.v.baselineStore.(BootEntryRepinStorer)
	if err := bs.RepinBootEntries(c.id, c.pinned, other.PCR1, nil,
		time.Now()); err != nil {
		t.Fatal(err)
	}
	_ = rs.RecordBootEvidence(c.id, pinnedLog, 0, false)
	if c.try() {
		t.Fatal("re-pinned over a moved row")
	}
	if c.pinnedNow(t) != other {
		t.Fatal("race refusal moved the pin")
	}
}
