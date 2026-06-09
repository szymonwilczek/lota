// SPDX-License-Identifier: MIT
// LOTA Verifier - Kernel trust extraction tests

package verify

import (
	"testing"
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
		{PCRIndex: 7, EventType: EvEFIVariableDriverConfig,
			EventData: encodeUEFIVariableData(efiGlobalVariableGUID, "PK", []byte{0xaa})},
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
		{PCRIndex: 7, EventType: EvEFIVariableDriverConfig,
			EventData: encodeUEFIVariableData(otherGUID, "SecureBoot", []byte{0x01})},
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
		{PCRIndex: 8, EventType: EvIPL,
			EventData: []byte("grub_cmd: linux (hd1,gpt2)/vmlinuz root=UUID=abc ro quiet\x00")},
		{PCRIndex: 8, EventType: EvIPL,
			EventData: []byte("kernel_cmdline: (hd1,gpt2)/vmlinuz root=UUID=abc ro quiet\x00")},
	}}
	got := ExtractKernelCmdlines(parsed)
	if len(got) != 1 || got[0] != "root=UUID=abc ro quiet" {
		t.Errorf("unexpected cmdlines: %q", got)
	}
}

func TestExtractKernelCmdlines_GrubCmdFallback(t *testing.T) {
	t.Log("TEST: grub_cmd linux event is the fallback source")

	parsed := &ParsedEventLog{Entries: []EventLogEntry{
		{PCRIndex: 8, EventType: EvIPL,
			EventData: []byte("grub_cmd: set root=hd1\x00")},
		{PCRIndex: 8, EventType: EvIPL,
			EventData: []byte("grub_cmd: linuxefi /vmlinuz root=UUID=abc ro\x00")},
	}}
	got := ExtractKernelCmdlines(parsed)
	if len(got) != 1 || got[0] != "root=UUID=abc ro" {
		t.Errorf("unexpected cmdlines: %q", got)
	}
}

func TestExtractKernelCmdlines_IgnoresOtherPCRs(t *testing.T) {
	t.Log("TEST: EV_IPL events outside PCR 8 are ignored")

	parsed := &ParsedEventLog{Entries: []EventLogEntry{
		{PCRIndex: 9, EventType: EvIPL,
			EventData: []byte("kernel_cmdline: /vmlinuz init=/bin/sh\x00")},
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
