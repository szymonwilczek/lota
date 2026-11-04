// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

func signatureList(sigType [16]byte, sigs ...[]byte) []byte {
	const owner = 16
	size := owner + len(sigs[0])
	list := append([]byte{}, sigType[:]...)
	list = binary.LittleEndian.AppendUint32(list, uint32(28+size*len(sigs)))
	list = binary.LittleEndian.AppendUint32(list, 0)
	list = binary.LittleEndian.AppendUint32(list, uint32(size))
	for _, sig := range sigs {
		list = append(list, make([]byte, owner)...)
		list = append(list, sig...)
	}
	return list
}

func testKeyCert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Owner"},
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func mokEvents(mokDigest [32]byte, label string) *ParsedEventLog {
	other := sha256.Sum256([]byte("other"))
	return &ParsedEventLog{Entries: []EventLogEntry{
		{PCRIndex: 14, EventType: EvNoAction, Digests: map[uint16][]byte{AlgSHA256: other[:]}},
		{PCRIndex: 14, EventType: EvIPL, Digests: map[uint16][]byte{AlgSHA256: mokDigest[:]},
			EventData: []byte(label + "\x00")},
		{PCRIndex: 14, EventType: EvIPL, Digests: map[uint16][]byte{AlgSHA256: other[:]},
			EventData: []byte("MokListX\x00")},
	}}
}

func TestParseSignatureLists(t *testing.T) {
	cert := testKeyCert(t)
	hash := sha256.Sum256([]byte("binary"))
	data := append(signatureList(efiCertX509GUID, cert),
		signatureList(efiCertSHA256GUID, hash[:], hash[:])...)

	keys := parseSignatureLists(data)
	if len(keys) != 3 {
		t.Fatalf("got %d keys, want 3: %+v", len(keys), keys)
	}
	fingerprint := sha256.Sum256(cert)
	if keys[0].Type != "x509" || keys[0].SHA256 != hex.EncodeToString(fingerprint[:]) ||
		keys[0].Subject != "CN=Test Owner" {
		t.Errorf("certificate entry: %+v", keys[0])
	}
	if keys[1].Type != "sha256" || keys[1].SHA256 != hex.EncodeToString(hash[:]) || keys[1].Subject != "" {
		t.Errorf("hash entry: %+v", keys[1])
	}

	// a certificate that does not parse still shows, by fingerprint
	broken := parseSignatureLists(signatureList(efiCertX509GUID, []byte("not-a-certificate")))
	if len(broken) != 1 || broken[0].Subject != "" || broken[0].SHA256 == "" {
		t.Errorf("unparsable certificate: %+v", broken)
	}

	// an unknown type is named by its GUID
	unknown := parseSignatureLists(signatureList([16]byte{0xAB}, []byte("data")))
	if len(unknown) != 1 || unknown[0].Type != hex.EncodeToString(append([]byte{0xAB}, make([]byte, 15)...)) {
		t.Errorf("unknown type: %+v", unknown)
	}
}

// walk stops at a malformed record and keeps what came before it
func TestParseSignatureLists_Malformed(t *testing.T) {
	good := signatureList(efiCertSHA256GUID, make([]byte, 32))

	mutate := func(offset int, value uint32) []byte {
		bad := append([]byte{}, good...)
		binary.LittleEndian.PutUint32(bad[offset:], value)
		return append(append([]byte{}, good...), bad...)
	}
	for name, data := range map[string][]byte{
		"list past the end":   mutate(16, 0xFFFFFFFF),
		"list under header":   mutate(16, 4),
		"header past list":    mutate(20, 0xFFFFFFF0),
		"entry only an owner": mutate(24, 16),
		"short tail":          append(append([]byte{}, good...), 1, 2, 3),
	} {
		if keys := parseSignatureLists(data); len(keys) != 1 {
			t.Errorf("%s: got %d keys, want 1", name, len(keys))
		}
	}
}

func TestExtractMachineKeys_MOKState(t *testing.T) {
	list := signatureList(efiCertSHA256GUID, make([]byte, 32))
	sum := sha256.Sum256(list)
	otherList := signatureList(efiCertSHA256GUID, append(make([]byte, 31), 1))
	otherSum := sha256.Sum256(otherList)

	tests := []struct {
		name  string
		log   *ParsedEventLog
		sent  []byte
		state string
		keys  int
	}{
		{"list matches the measurement", mokEvents(sum, "MokList"), list, MOKListed, 1},
		{"list off the measurement", mokEvents(otherSum, "MokList"), list, MOKUnproven, 0},
		{"nothing sent", mokEvents(sum, "MokList"), nil, MOKUnproven, 0},
		{"first event relabelled", mokEvents(sum, "MokListX"), list, MOKUnproven, 0},
		{"no shim", &ParsedEventLog{}, list, MOKNotMeasured, 0},
		{"no log", nil, list, MOKUnproven, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractMachineKeys(tt.log, tt.sent)
			if got.MOKState != tt.state || len(got.MOK) != tt.keys {
				t.Errorf("got %s with %d keys, want %s with %d", got.MOKState, len(got.MOK), tt.state, tt.keys)
			}
		})
	}
}

// second list event named MokList cannot stand in for the first
func TestExtractMachineKeys_OnlyFirstEventCounts(t *testing.T) {
	list := signatureList(efiCertSHA256GUID, make([]byte, 32))
	sum := sha256.Sum256(list)
	first := sha256.Sum256([]byte("real list"))

	log := mokEvents(first, "foo")
	log.Entries[2].Digests[AlgSHA256] = sum[:]
	log.Entries[2].EventData = []byte("MokList\x00")

	if got := ExtractMachineKeys(log, list); got.MOKState != MOKUnproven {
		t.Errorf("state %s, want %s", got.MOKState, MOKUnproven)
	}
}

func TestExtractMachineKeys_DB(t *testing.T) {
	db := signatureList(efiCertSHA256GUID, make([]byte, 32))
	log := &ParsedEventLog{Entries: []EventLogEntry{
		measuredEntry(7, EvEFIVariableDriverConfig,
			encodeUEFIVariableData(efiGlobalVariableGUID, "db", db)),
	}}

	got := ExtractMachineKeys(log, nil)
	if len(got.DB) != 1 || got.DB[0].Type != "sha256" {
		t.Errorf("db: %+v", got.DB)
	}
	if got.MOK == nil {
		t.Error("MOK must encode as an empty list, not null")
	}
}

func TestCertSubject(t *testing.T) {
	if got := certSubject(testKeyCert(t)); got != "CN=Test Owner" {
		t.Errorf("subject: %q", got)
	}

	subject, err := asn1.Marshal(pkix.Name{CommonName: "Test Vendor"}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	null := asn1.RawValue{FullBytes: []byte{asn1.TagNull, 0}}
	negative, err := asn1.Marshal(struct {
		TBS struct {
			Version  int `asn1:"optional,explicit,tag:0"`
			Serial   *big.Int
			SigAlg   asn1.RawValue
			Issuer   asn1.RawValue
			Validity asn1.RawValue
			Subject  asn1.RawValue
		}
	}{TBS: struct {
		Version  int `asn1:"optional,explicit,tag:0"`
		Serial   *big.Int
		SigAlg   asn1.RawValue
		Issuer   asn1.RawValue
		Validity asn1.RawValue
		Subject  asn1.RawValue
	}{2, big.NewInt(-1), null, null, null, asn1.RawValue{FullBytes: subject}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := certSubject(negative); got != "CN=Test Vendor" {
		t.Errorf("negative serial subject: %q", got)
	}

	if got := certSubject([]byte("not a certificate")); got != "" {
		t.Errorf("garbage subject: %q", got)
	}
}

func mokEvent(digest [32]byte, name string) EventLogEntry {
	return EventLogEntry{PCRIndex: 14, EventType: EvIPL,
		Digests: map[uint16][]byte{AlgSHA256: digest[:]}, EventData: []byte(name + "\x00")}
}

// what shim measures on a Secure Boot host: the MOK list, the denylist and the
// trust flag
func mokBootEntries(list []byte, trusted byte) []EventLogEntry {
	return []EventLogEntry{
		measuredSecureBootEntry(1),
		mokEvent(sha256.Sum256(list), "MokList"),
		mokEvent(sha256.Sum256([]byte("denylist")), "MokListX"),
		mokEvent(sha256.Sum256([]byte{trusted}), "MokListTrusted"),
	}
}

func TestMOKPCR14Change(t *testing.T) {
	other := mokEvent(sha256.Sum256([]byte("other")), "Other")
	moved := mokEvent(sha256.Sum256([]byte("moved")), "Other")
	renamed := mokBootEntries([]byte("list-a"), 0)
	renamed[1].EventData = []byte("MokListX\x00")

	tests := []struct {
		name    string
		pinned  []EventLogEntry
		current []EventLogEntry
		want    []string
	}{
		{"list moved", mokBootEntries([]byte("list-a"), 0),
			mokBootEntries([]byte("list-b"), 0), []string{"MokList"}},
		{"trust flag moved", mokBootEntries([]byte("list-a"), 0),
			mokBootEntries([]byte("list-a"), 1), []string{"MokListTrusted"}},
		{"other event moved", append(mokBootEntries([]byte("list-a"), 0), other),
			append(mokBootEntries([]byte("list-b"), 0), moved), nil},
		{"event added", mokBootEntries([]byte("list-a"), 0),
			append(mokBootEntries([]byte("list-b"), 0), other), nil},
		{"name moved", mokBootEntries([]byte("list-a"), 0), renamed, nil},
		{"nothing moved", mokBootEntries([]byte("list-a"), 0),
			mokBootEntries([]byte("list-a"), 0), nil},
		{"no shim", []EventLogEntry{measuredSecureBootEntry(1)},
			mokBootEntries([]byte("list-a"), 0), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mokPCR14Change(&ParsedEventLog{Entries: tt.pinned},
				&ParsedEventLog{Entries: tt.current})
			if tt.want == nil {
				if err == nil {
					t.Fatalf("expected refusal, got %v", got)
				}
				return
			}
			if err != nil || !slices.Equal(got, tt.want) {
				t.Fatalf("got %v, %v; want %v", got, err, tt.want)
			}
		})
	}
}

type mokRepinCase struct {
	v       *Verifier
	id      string
	pinned  [types.HashSize]byte
	pcr14   [types.HashSize]byte
	report  *types.AttestationReport
	facts   *BootFacts
	logNext []byte
}

// a client pinned on one MOK list that boots with another
func newMOKRepinCase(t *testing.T, profile string, current []EventLogEntry) *mokRepinCase {
	t.Helper()

	agent := fixtureAgentHash()
	v := NewVerifier(DefaultConfig(), newCertVerifier(t))
	policy := DefaultPolicy()
	policy.Profile = profile
	policy.RequireSecureBoot = true
	policy.AgentHashes = []string{hex.EncodeToString(agent[:])}
	if err := v.AddPolicy(policy); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}

	pinnedLog := buildTestEventLog(mokBootEntries([]byte("list-a"), 0))
	pinnedParsed, err := ParseEventLog(pinnedLog)
	if err != nil {
		t.Fatal(err)
	}
	c := &mokRepinCase{v: v, id: "mok-client"}
	c.pinned = DeriveLockedBootCommitmentPCR14(PCR14BaselineFromEventLog(pinnedParsed), agent)
	b := boot(0x10, 0x11, 0x17)
	v.baselineStore.(AtomicBaselineStorer).CheckAndUpdateAttestation(c.id, c.pinned, agent, &b)
	if err := v.baselineStore.(ReanchorStorer).RecordBootEvidence(c.id, pinnedLog, 0, false); err != nil {
		t.Fatal(err)
	}

	c.logNext = buildTestEventLog(current)
	parsed, err := ParseEventLog(c.logNext)
	if err != nil {
		t.Fatal(err)
	}
	c.pcr14 = DeriveLockedBootCommitmentPCR14(PCR14BaselineFromEventLog(parsed), agent)
	c.report = &types.AttestationReport{EventLog: c.logNext, MokList: []byte("list-b")}
	c.report.System.AgentHash = agent
	c.facts = &BootFacts{Parsed: parsed, SecureBootTrusted: true,
		SecureBoot: SecureBootState{Found: true, Enabled: true}}
	return c
}

func (c *mokRepinCase) try() bool {
	return c.v.tryMOKRepin(slog.Default(), c.id, "", c.pinned, c.pcr14, c.report, c.facts)
}

func (c *mokRepinCase) pinnedNow() [types.HashSize]byte {
	return c.v.baselineStore.GetBaseline(c.id).PCR14
}

func TestTryMOKRepin_FollowsAnEnrolledKey(t *testing.T) {
	c := newMOKRepinCase(t, ProfileConsumer, mokBootEntries([]byte("list-b"), 0))
	if !c.try() {
		t.Fatal("a change confined to the MOK list must re-pin")
	}
	if c.pinnedNow() != c.pcr14 {
		t.Fatal("pin did not move to the reported register")
	}
	st := c.v.baselineStore.(ReanchorStorer).GetReanchorState(c.id)
	if !bytes.Equal(st.EventLogBaseline, c.logNext) {
		t.Fatal("boot evidence did not move with the pin")
	}
}

func TestTryMOKRepin_Refusals(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		current []EventLogEntry
		mutate  func(*mokRepinCase)
	}{
		{"enterprise", ProfileEnterprise, mokBootEntries([]byte("list-b"), 0), nil},
		{"no secure boot", ProfileConsumer, mokBootEntries([]byte("list-b"), 0),
			func(c *mokRepinCase) { c.facts.SecureBoot.Enabled = false }},
		{"list not sent", ProfileConsumer, mokBootEntries([]byte("list-b"), 0),
			func(c *mokRepinCase) { c.report.MokList = nil }},
		{"other event", ProfileConsumer,
			append(mokBootEntries([]byte("list-b"), 0),
				mokEvent(sha256.Sum256([]byte("other")), "Other")), nil},
		{"log off the pin", ProfileConsumer, mokBootEntries([]byte("list-b"), 0),
			func(c *mokRepinCase) { c.pinned[0] ^= 1 }},
		{"no log on record", ProfileConsumer, mokBootEntries([]byte("list-b"), 0),
			func(c *mokRepinCase) {
				_ = c.v.baselineStore.(ReanchorStorer).RecordBootEvidence(c.id, nil, 0, false)
			}},
		{"log unparseable", ProfileConsumer, mokBootEntries([]byte("list-b"), 0),
			func(c *mokRepinCase) {
				_ = c.v.baselineStore.(ReanchorStorer).RecordBootEvidence(c.id, []byte{1}, 0, false)
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newMOKRepinCase(t, tt.profile, tt.current)
			before := c.pinnedNow()
			if tt.mutate != nil {
				tt.mutate(c)
			}
			if c.try() {
				t.Fatal("re-pinned")
			}
			if c.pinnedNow() != before {
				t.Fatal("refusal moved the pin")
			}
		})
	}
}

// the row moved after the decision read it: the write refuses
func TestTryMOKRepin_RaceRefused(t *testing.T) {
	c := newMOKRepinCase(t, ProfileConsumer, mokBootEntries([]byte("list-b"), 0))
	var other [types.HashSize]byte
	other[0] = 0x99
	if err := c.v.baselineStore.(PCR14RepinStorer).RepinPCR14(c.id, c.pinned, other, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	_ = c.v.baselineStore.(ReanchorStorer).RecordBootEvidence(c.id,
		buildTestEventLog(mokBootEntries([]byte("list-a"), 0)), 0, false)
	if c.try() {
		t.Fatal("re-pinned over a moved row")
	}
	if c.pinnedNow() != other {
		t.Fatal("race refusal moved the pin")
	}
}
