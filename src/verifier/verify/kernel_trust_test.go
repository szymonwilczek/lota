// SPDX-License-Identifier: MIT
// LOTA Verifier - Kernel trust extraction tests

package verify

import (
	"crypto/sha256"
	"testing"

	"github.com/szymonwilczek/lota/verifier/types"
)

func secureBootEntry(value []byte) EventLogEntry {
	return EventLogEntry{
		PCRIndex:  7,
		EventType: EvEFIVariableDriverConfig,
		EventData: encodeUEFIVariableData(efiGlobalVariableGUID, "SecureBoot", value),
	}
}

func TestExtractSecureBootState_Enabled(t *testing.T) {
	t.Log("TEST: SecureBoot variable 0x01 reports enabled")

	parsed := &ParsedEventLog{Entries: []EventLogEntry{
		{
			PCRIndex: 7, EventType: EvEFIVariableDriverConfig,
			EventData: encodeUEFIVariableData(efiGlobalVariableGUID, "PK", []byte{0xaa}),
		},
		secureBootEntry([]byte{0x01}),
	}}
	st, err := ExtractSecureBootState(parsed)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if !st.Found || !st.Enabled {
		t.Errorf("want found+enabled, got %+v", st)
	}
}

func TestExtractSecureBootState_Disabled(t *testing.T) {
	t.Log("TEST: SecureBoot variable 0x00 reports disabled")

	parsed := &ParsedEventLog{Entries: []EventLogEntry{secureBootEntry([]byte{0x00})}}
	st, err := ExtractSecureBootState(parsed)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if !st.Found || st.Enabled {
		t.Errorf("want found+disabled, got %+v", st)
	}
}

func TestExtractSecureBootState_Missing(t *testing.T) {
	t.Log("TEST: Log without a SecureBoot variable reports not-found")

	otherGUID := [16]byte{0x01}
	parsed := &ParsedEventLog{Entries: []EventLogEntry{
		{
			PCRIndex: 7, EventType: EvEFIVariableDriverConfig,
			EventData: encodeUEFIVariableData(otherGUID, "SecureBoot", []byte{0x01}),
		},
		{PCRIndex: 7, EventType: EvSeparator, EventData: []byte{0, 0, 0, 0}},
	}}
	st, err := ExtractSecureBootState(parsed)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if st.Found {
		t.Errorf("want not-found, got %+v", st)
	}
}

func TestExtractSecureBootState_Conflicting(t *testing.T) {
	t.Log("TEST: Conflicting SecureBoot measurements fail closed")

	parsed := &ParsedEventLog{Entries: []EventLogEntry{
		secureBootEntry([]byte{0x01}),
		secureBootEntry([]byte{0x00}),
	}}
	if _, err := ExtractSecureBootState(parsed); err == nil {
		t.Error("conflicting measurements not rejected")
	}
}

func TestExtractSecureBootState_MalformedVariable(t *testing.T) {
	t.Log("TEST: Malformed PCR 7 variable event fails closed")

	parsed := &ParsedEventLog{Entries: []EventLogEntry{
		{PCRIndex: 7, EventType: EvEFIVariableDriverConfig, EventData: []byte{0x01, 0x02}},
	}}
	if _, err := ExtractSecureBootState(parsed); err == nil {
		t.Error("malformed variable event not rejected")
	}
}

func TestExtractSecureBootState_OversizeValue(t *testing.T) {
	t.Log("TEST: SecureBoot variable with unexpected size fails closed")

	parsed := &ParsedEventLog{Entries: []EventLogEntry{secureBootEntry([]byte{0x01, 0x00})}}
	if _, err := ExtractSecureBootState(parsed); err == nil {
		t.Error("oversize SecureBoot value not rejected")
	}
}

func TestExtractKernelCmdlines_KernelCmdlineEvent(t *testing.T) {
	t.Log("TEST: kernel_cmdline EV_IPL event yields the parameter string")

	parsed := &ParsedEventLog{Entries: []EventLogEntry{
		{
			PCRIndex: 8, EventType: EvIPL,
			EventData: []byte("grub_cmd: linux (hd1,gpt2)/vmlinuz root=UUID=abc ro quiet\x00"),
		},
		{
			PCRIndex: 8, EventType: EvIPL,
			EventData: []byte("kernel_cmdline: (hd1,gpt2)/vmlinuz root=UUID=abc ro quiet\x00"),
		},
	}}
	got := ExtractKernelCmdlines(parsed)
	if len(got) != 1 || got[0] != "root=UUID=abc ro quiet" {
		t.Errorf("unexpected cmdlines: %q", got)
	}
}

func TestExtractKernelCmdlines_GrubCmdFallback(t *testing.T) {
	t.Log("TEST: grub_cmd linux event is the fallback source")

	parsed := &ParsedEventLog{Entries: []EventLogEntry{
		{
			PCRIndex: 8, EventType: EvIPL,
			EventData: []byte("grub_cmd: set root=hd1\x00"),
		},
		{
			PCRIndex: 8, EventType: EvIPL,
			EventData: []byte("grub_cmd: linuxefi /vmlinuz root=UUID=abc ro\x00"),
		},
	}}
	got := ExtractKernelCmdlines(parsed)
	if len(got) != 1 || got[0] != "root=UUID=abc ro" {
		t.Errorf("unexpected cmdlines: %q", got)
	}
}

func TestExtractKernelCmdlines_IgnoresOtherPCRs(t *testing.T) {
	t.Log("TEST: EV_IPL events outside PCR 8 are ignored")

	parsed := &ParsedEventLog{Entries: []EventLogEntry{
		{
			PCRIndex: 9, EventType: EvIPL,
			EventData: []byte("kernel_cmdline: /vmlinuz init=/bin/sh\x00"),
		},
	}}
	if got := ExtractKernelCmdlines(parsed); len(got) != 0 {
		t.Errorf("unexpected cmdlines: %q", got)
	}
}

func TestExtractKernelCmdlines_EmptyParams(t *testing.T) {
	t.Log("TEST: cmdline with only the image path yields an empty string")

	parsed := &ParsedEventLog{Entries: []EventLogEntry{
		{PCRIndex: 8, EventType: EvIPL, EventData: []byte("kernel_cmdline: /vmlinuz\x00")},
	}}
	got := ExtractKernelCmdlines(parsed)
	if len(got) != 1 || got[0] != "" {
		t.Errorf("unexpected cmdlines: %q", got)
	}
}

func TestExtractKernelCmdlines_MultipleKernelCmdlines(t *testing.T) {
	t.Log("TEST: every measured kernel_cmdline event is returned")

	parsed := &ParsedEventLog{Entries: []EventLogEntry{
		{PCRIndex: 8, EventType: EvIPL, EventData: []byte("kernel_cmdline: /vmlinuz ro quiet\x00")},
		{PCRIndex: 8, EventType: EvIPL, EventData: []byte("kernel_cmdline: /vmlinuz ro init=/bin/sh\x00")},
	}}
	got := ExtractKernelCmdlines(parsed)
	if len(got) != 2 {
		t.Fatalf("want 2 cmdlines, got %q", got)
	}
	if got[0] != "ro quiet" || got[1] != "ro init=/bin/sh" {
		t.Errorf("unexpected cmdlines: %q", got)
	}
}

func TestMatchCmdlineDeny_CleanFedoraCmdline(t *testing.T) {
	t.Log("TEST: Stock Fedora GRUB cmdline passes the builtin denylist")

	cmdline := "root=UUID=bfcb1962-9c52-4077-9ec3-da7fec4314fb ro rootflags=subvol=root " +
		"rhgb quiet drm.edid_firmware=DP-1:edid/a.bin,HDMI-A-1:edid/b.bin usbcore.autosuspend=-1"
	if hits := MatchCmdlineDeny(cmdline, builtinCmdlineDeny); len(hits) != 0 {
		t.Errorf("clean cmdline matched denylist: %v", hits)
	}
}

func TestMatchCmdlineDeny_BuiltinEntries(t *testing.T) {
	t.Log("TEST: Every builtin denylist class is caught")

	cases := []string{
		"ro quiet init=/bin/sh",
		"ro rdinit=/bin/sh",
		"ro rd.break",
		"ro rd.break=pre-mount",
		"ro lockdown=none",
		"ro module.sig_enforce=0",
		"ro selinux=0",
		"ro enforcing=0",
		"ro apparmor=0",
		"ro security=none",
		"ro systemd.debug_shell",
		"ro systemd.debug_shell=1",
		"ro kgdboc=ttyS0,115200",
	}
	for _, c := range cases {
		if hits := MatchCmdlineDeny(c, builtinCmdlineDeny); len(hits) == 0 {
			t.Errorf("dangerous cmdline %q not matched", c)
		}
	}
}

func TestMatchCmdlineDeny_DashUnderscoreEquivalence(t *testing.T) {
	t.Log("TEST: Kernel '-'/'_' parameter-name equivalence cannot bypass rules")

	if hits := MatchCmdlineDeny("ro module.sig-enforce=0", builtinCmdlineDeny); len(hits) == 0 {
		t.Error("dash-spelled module.sig-enforce=0 not matched")
	}
	if hits := MatchCmdlineDeny("ro systemd.debug-shell=1", builtinCmdlineDeny); len(hits) == 0 {
		t.Error("dash-spelled systemd.debug-shell not matched")
	}
}

func TestMatchCmdlineDeny_ExactValueRules(t *testing.T) {
	t.Log("TEST: Exact key=value rules do not match legitimate values")

	clean := []string{
		"ro lockdown=integrity",
		"ro security=selinux",
		"ro enforcing=1",
		"ro selinux=1",
	}
	for _, c := range clean {
		if hits := MatchCmdlineDeny(c, builtinCmdlineDeny); len(hits) != 0 {
			t.Errorf("legitimate cmdline %q matched: %v", c, hits)
		}
	}
}

func TestMatchCmdlineDeny_OperatorExtension(t *testing.T) {
	t.Log("TEST: Operator cmdline_deny entries extend the builtin set")

	policy := &PCRPolicy{CmdlineDeny: []string{"nokaslr"}}
	deny := policy.EffectiveCmdlineDeny()
	if hits := MatchCmdlineDeny("ro nokaslr", deny); len(hits) == 0 {
		t.Error("operator-denied nokaslr not matched")
	}
	if hits := MatchCmdlineDeny("ro init=/bin/sh", deny); len(hits) == 0 {
		t.Error("builtin rule lost after operator extension")
	}
}

// builds an entry whose SHA-256 digest is derived from its event data,
// mirroring how GRUB/firmware measure before logging
func measuredEntry(pcr uint32, eventType uint32, data []byte) EventLogEntry {
	d := sha256.Sum256(data)
	return EventLogEntry{
		PCRIndex:  pcr,
		EventType: eventType,
		Digests:   map[uint16][]byte{AlgSHA256: d[:]},
		EventData: data,
	}
}

// builds a report whose quoted PCR values match the replay of entries
func reportForEntries(t *testing.T, entries []EventLogEntry, mask uint32) *types.AttestationReport {
	t.Helper()

	report := &types.AttestationReport{}
	report.EventLog = buildTestEventLog(entries)

	parsed, err := ParseEventLog(report.EventLog)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	replay, err := ReplayEventLog(parsed)
	if err != nil {
		t.Fatalf("replay failed: %v", err)
	}

	report.TPM.PCRMask = mask
	report.TPM.PCRValues = replay.PCRValues
	return report
}

func measuredSecureBootEntry(value byte) EventLogEntry {
	return measuredEntry(7, EvEFIVariableDriverConfig,
		encodeUEFIVariableData(efiGlobalVariableGUID, "SecureBoot", []byte{value}))
}

func measuredCmdlineEntry(cmdline string) EventLogEntry {
	return measuredEntry(8, EvIPL, []byte("kernel_cmdline: /vmlinuz "+cmdline+"\x00"))
}

func secureBootPolicy() *PCRPolicy {
	return &PCRPolicy{Name: "sb", RequireSecureBoot: true}
}

func cmdlinePolicy() *PCRPolicy {
	return &PCRPolicy{Name: "cmdline", RequireCmdlinePolicy: true}
}

func verifyWithPolicy(t *testing.T, policy *PCRPolicy, report *types.AttestationReport, enforcePCR8 bool) error {
	t.Helper()

	facts, err := VerifyEventLogWithPolicy(report, enforcePCR8)
	if err != nil {
		return err
	}

	v := NewPCRVerifier()
	if err := v.AddPolicy(policy); err != nil {
		t.Fatalf("AddPolicy failed: %v", err)
	}
	return v.VerifyReportWithFacts(report, facts)
}

func TestSecureBootGate_EnabledPasses(t *testing.T) {
	t.Log("SECURITY TEST: event-log Secure Boot enabled passes the gate")

	report := reportForEntries(t, []EventLogEntry{measuredSecureBootEntry(0x01)}, 1<<7)
	if err := verifyWithPolicy(t, secureBootPolicy(), report, false); err != nil {
		t.Errorf("enabled Secure Boot rejected: %v", err)
	}
}

func TestSecureBootGate_DisabledRejected(t *testing.T) {
	t.Log("SECURITY TEST: event-log Secure Boot disabled is rejected")

	report := reportForEntries(t, []EventLogEntry{measuredSecureBootEntry(0x00)}, 1<<7)
	if err := verifyWithPolicy(t, secureBootPolicy(), report, false); err == nil {
		t.Error("disabled Secure Boot not rejected")
	}
}

func TestSecureBootGate_MissingMeasurementRejected(t *testing.T) {
	t.Log("SECURITY TEST: log without a SecureBoot measurement is rejected")

	report := reportForEntries(t, []EventLogEntry{
		measuredEntry(7, EvSeparator, []byte{0, 0, 0, 0}),
	}, 1<<7)
	if err := verifyWithPolicy(t, secureBootPolicy(), report, false); err == nil {
		t.Error("missing SecureBoot measurement not rejected")
	}
}

func TestSecureBootGate_UnquotedPCR7Rejected(t *testing.T) {
	t.Log("SECURITY TEST: SecureBoot fact without PCR 7 in the quote is untrusted")

	report := reportForEntries(t, []EventLogEntry{measuredSecureBootEntry(0x01)}, 1<<0)
	if err := verifyWithPolicy(t, secureBootPolicy(), report, false); err == nil {
		t.Error("unquoted PCR 7 not rejected")
	}
}

func TestSecureBootGate_ForgedEventRejected(t *testing.T) {
	t.Log("SECURITY TEST: forged SecureBoot event breaks PCR 7 replay")

	// quoted PCRs derived from the honest log (Secure Boot disabled)
	report := reportForEntries(t, []EventLogEntry{measuredSecureBootEntry(0x00)}, 1<<7)
	// attacker swaps in a log claiming Secure Boot is enabled
	report.EventLog = buildTestEventLog([]EventLogEntry{measuredSecureBootEntry(0x01)})

	if err := verifyWithPolicy(t, secureBootPolicy(), report, false); err == nil {
		t.Error("forged SecureBoot event not rejected")
	}
}

func TestSecureBootGate_SelfReportedFlagIgnored(t *testing.T) {
	t.Log("SECURITY TEST: agent-reported FlagSecureBoot cannot satisfy the gate")

	report := reportForEntries(t, []EventLogEntry{measuredSecureBootEntry(0x00)}, 1<<7)
	report.Header.Flags |= types.FlagSecureBoot

	if err := verifyWithPolicy(t, secureBootPolicy(), report, false); err == nil {
		t.Error("self-reported flag overrode the firmware measurement")
	}
}

func TestCmdlineGate_CleanCmdlinePasses(t *testing.T) {
	t.Log("SECURITY TEST: clean measured cmdline passes the gate")

	report := reportForEntries(t, []EventLogEntry{
		measuredCmdlineEntry("root=UUID=abc ro rhgb quiet"),
	}, 1<<8)
	if err := verifyWithPolicy(t, cmdlinePolicy(), report, true); err != nil {
		t.Errorf("clean cmdline rejected: %v", err)
	}
}

func TestCmdlineGate_DangerousCmdlineRejected(t *testing.T) {
	t.Log("SECURITY TEST: denylisted cmdline parameter is rejected")

	report := reportForEntries(t, []EventLogEntry{
		measuredCmdlineEntry("root=UUID=abc ro lockdown=none"),
	}, 1<<8)
	if err := verifyWithPolicy(t, cmdlinePolicy(), report, true); err == nil {
		t.Error("lockdown=none not rejected")
	}
}

func TestCmdlineGate_ForgedEventRejectedWhenEnforced(t *testing.T) {
	t.Log("SECURITY TEST: forged cmdline event breaks PCR 8 replay when enforced")

	// quoted PCRs derived from the honest log (dangerous cmdline)
	report := reportForEntries(t, []EventLogEntry{
		measuredCmdlineEntry("ro init=/bin/sh"),
	}, 1<<8)
	// attacker swaps in a log claiming a clean cmdline
	report.EventLog = buildTestEventLog([]EventLogEntry{
		measuredCmdlineEntry("ro quiet"),
	})

	if _, err := VerifyEventLogWithPolicy(report, true); err == nil {
		t.Error("forged cmdline event not rejected with PCR 8 enforcement")
	}
	// without enforcement the forgery is invisible to the consistency
	// check: exactly why the cmdline gate must enforce PCR 8
	if _, err := VerifyEventLogWithPolicy(report, false); err != nil {
		t.Errorf("unexpected error without PCR 8 enforcement: %v", err)
	}
}

func TestCmdlineGate_StrippedLogRejected(t *testing.T) {
	t.Log("SECURITY TEST: log stripped of PCR 8 events cannot fake a non-GRUB host")

	// honest GRUB host: non-zero quoted PCR 8
	report := reportForEntries(t, []EventLogEntry{
		measuredCmdlineEntry("ro init=/bin/sh"),
	}, 1<<8)
	// attacker removes every PCR 8 event from the log
	report.EventLog = buildTestEventLog([]EventLogEntry{
		measuredEntry(7, EvSeparator, []byte{0, 0, 0, 0}),
	})

	if err := verifyWithPolicy(t, cmdlinePolicy(), report, true); err == nil {
		t.Error("stripped PCR 8 log not rejected")
	}
}

func TestCmdlineGate_NonGRUBHostSkipped(t *testing.T) {
	t.Log("TEST: zero quoted PCR 8 with no PCR 8 events skips the cmdline check")

	report := reportForEntries(t, []EventLogEntry{
		measuredEntry(7, EvSeparator, []byte{0, 0, 0, 0}),
	}, (1<<7)|(1<<8))
	if err := verifyWithPolicy(t, cmdlinePolicy(), report, true); err != nil {
		t.Errorf("non-GRUB host rejected: %v", err)
	}
}

func TestCmdlineGate_UnquotedPCR8Rejected(t *testing.T) {
	t.Log("SECURITY TEST: cmdline gate requires PCR 8 in the quote mask")

	report := reportForEntries(t, []EventLogEntry{
		measuredEntry(7, EvSeparator, []byte{0, 0, 0, 0}),
	}, 1<<7)
	if err := verifyWithPolicy(t, cmdlinePolicy(), report, true); err == nil {
		t.Error("missing PCR 8 quote coverage not rejected")
	}
}

func TestGetRequiredMask_CmdlinePolicyForcesPCR8(t *testing.T) {
	t.Log("TEST: require_cmdline_policy forces PCR 8 into the required mask")

	if mask := cmdlinePolicy().GetRequiredMask(); mask&(1<<8) == 0 {
		t.Errorf("PCR 8 missing from required mask 0x%08x", mask)
	}
	plain := &PCRPolicy{Name: "plain"}
	if mask := plain.GetRequiredMask(); mask&(1<<8) != 0 {
		t.Errorf("PCR 8 unexpectedly in required mask 0x%08x", mask)
	}
}
