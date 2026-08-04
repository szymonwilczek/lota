// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Kernel trust from event-log semantics
//
// Machine-independent kernel trust controls derived from the TPM event
// log instead of raw PCR pins or agent-reported flags:
//   - Secure Boot state from the firmware-measured SecureBoot variable
//     (PCR 7, EV_EFI_VARIABLE_DRIVER_CONFIG)
//   - kernel command line from the GRUB measurement (PCR 8, EV_IPL)
//
// Extracted values are trustworthy only when the corresponding PCR
// is covered by the TPM quote and the event-log replay matches the
// quoted value.
// Callers must gate on those conditions (see BootFacts).

package verify

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/szymonwilczek/lota/verifier/types"
)

// firmware-measured Secure Boot configuration recovered from the log
type SecureBootState struct {
	Found   bool
	Enabled bool
}

// scans PCR 7 EV_EFI_VARIABLE_DRIVER_CONFIG events for the EFI global
// "SecureBoot" variable.
// Enabled means a one-byte value of 0x01.
// Malformed or conflicting SecureBoot measurements are errors so the
// caller fails closed.
func ExtractSecureBootState(parsed *ParsedEventLog) (SecureBootState, error) {
	var st SecureBootState
	if parsed == nil {
		return st, errors.New("nil event log")
	}

	for _, e := range parsed.Entries {
		if e.PCRIndex != 7 || e.EventType != EvEFIVariableDriverConfig {
			continue
		}
		v, err := parseUEFIVariableData(e.EventData)
		if err != nil {
			return SecureBootState{}, fmt.Errorf("malformed UEFI variable event on PCR 7: %w", err)
		}
		if v.VariableName != efiGlobalVariableGUID || v.UnicodeName != "SecureBoot" {
			continue
		}
		if len(v.VariableData) != 1 {
			return SecureBootState{}, fmt.Errorf("unexpected SecureBoot variable size: %d", len(v.VariableData))
		}

		enabled := v.VariableData[0] == 0x01
		if st.Found && st.Enabled != enabled {
			return SecureBootState{}, errors.New("conflicting SecureBoot measurements in event log")
		}
		st.Found = true
		st.Enabled = enabled
	}

	return st, nil
}

const (
	kernelCmdlinePrefix = "kernel_cmdline: "
	grubCmdPrefix       = "grub_cmd: "
)

// Returns the kernel command lines GRUB measured into PCR 8.
// Dedicated "kernel_cmdline: " EV_IPL event is the primary source;
// "grub_cmd: linux ..." events are the fallback for GRUB builds that do
// not emit it.
// Leading kernel image path token is stripped: it duplicates the per-machine
// boot device/path and carries no parameters.
// All returned command lines must satisfy the policy; only one of them
// booted, but the log does not say which.
func ExtractKernelCmdlines(parsed *ParsedEventLog) []string {
	if parsed == nil {
		return nil
	}

	var primary, fallback []string
	for _, e := range parsed.Entries {
		if e.PCRIndex != 8 || e.EventType != EvIPL {
			continue
		}
		s := parseIPLEventString(e.EventData)

		if rest, ok := strings.CutPrefix(s, kernelCmdlinePrefix); ok {
			primary = append(primary, stripImagePathToken(rest))
			continue
		}
		if rest, ok := strings.CutPrefix(s, grubCmdPrefix); ok {
			fields := strings.Fields(rest)
			if len(fields) >= 2 &&
				(fields[0] == "linux" || fields[0] == "linuxefi" || fields[0] == "linux16") {
				fallback = append(fallback, strings.Join(fields[2:], " "))
			}
		}
	}

	if len(primary) > 0 {
		return primary
	}
	return fallback
}

// drops the first whitespace-separated token (the kernel image path)
func stripImagePathToken(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	return ""
}

// builtinCmdlineDeny rejects parameters that defeat the signed kernel's
// integrity guarantees while staying machine-independent: none of them
// appear on a stock distribution command line. Rule forms:
//
//	"param"   bare flag or any valued form
//	"param="  any value
//	"param=v" exact key=value pair
var builtinCmdlineDeny = []string{
	"init=",         // arbitrary userspace entry point
	"rdinit=",       // arbitrary entry point via initramfs
	"rd.break",      // dracut pre-pivot root shell
	"lockdown=none", // disables kernel lockdown
	"module.sig_enforce=0",
	"selinux=0",
	"enforcing=0",
	"apparmor=0",
	"security=none",
	"systemd.debug_shell", // root shell on tty9
	"kgdboc=",             // kernel debugger console: live memory patching
}

// kernel parameter names treat '-' and '_' as equivalent
func normalizeParamKey(k string) string {
	return strings.ReplaceAll(k, "-", "_")
}

// reports whether a single cmdline token matches a deny rule
func cmdlineTokenMatches(token, rule string) bool {
	tKey, tVal, tHasVal := strings.Cut(token, "=")
	rKey, rVal, rHasVal := strings.Cut(rule, "=")
	if normalizeParamKey(tKey) != normalizeParamKey(rKey) {
		return false
	}
	if !rHasVal || rVal == "" {
		return true
	}
	return tHasVal && tVal == rVal
}

// returns the deny rules matched by any parameter on cmdline.
// Tokenization is whitespace-based and does not honor kernel quoting,
// so a denied key inside a quoted value still matches (fail closed).
func MatchCmdlineDeny(cmdline string, deny []string) []string {
	var hits []string
	seen := make(map[string]bool)
	for _, token := range strings.Fields(cmdline) {
		for _, rule := range deny {
			if !seen[rule] && cmdlineTokenMatches(token, rule) {
				seen[rule] = true
				hits = append(hits, rule)
			}
		}
	}
	return hits
}

// BootFacts carries the event-log-derived boot state the policy gates
// consume.
// *Trusted field is set only when the source PCR is covered by the quote
// mask and the event-log replay reproduces the quoted value,
// i.e. the TPM vouches for the log entries the fact came from
type BootFacts struct {
	SecureBoot        SecureBootState
	SecureBootTrusted bool // PCR 7 quoted + replay-consistent

	Cmdlines       []string
	CmdlineTrusted bool // PCR 8 quoted + replay-consistent
	PCR8Quoted     bool
	PCR8Reported   [types.HashSize]byte
	PCR8EventsSeen bool

	// Parsed is the event log already parsed for this verification, so
	// downstream consumers (re-anchor) reuse it instead of parsing the
	// same bytes again.
	// Set only after quote-consistency passed.
	Parsed *ParsedEventLog
}

// SecureBootAnchored reports whether the event-log facts prove Secure
// Boot enabled through a quote-authenticated PCR 7 replay.
// Boot enrollment gate uses this as the machine-independent anchor
// that permits per-device TOFU of the PCR 0/1/7 baseline:
// the boot-with-Secure-Boot-off cheat path is already rejected here,
// so the TOFU row degrades to a per-device rollback/consistency anchor
// rather than the sole firmware trust control.
func SecureBootAnchored(facts *BootFacts) bool {
	return facts != nil && facts.SecureBootTrusted &&
		facts.SecureBoot.Found && facts.SecureBoot.Enabled
}

// UEFIAnchored reports whether the event log proves the host booted via UEFI:
// the firmware measured the EFI global SecureBoot variable into PCR 7
// (EV_EFI_VARIABLE_DRIVER_CONFIG) and that PCR 7 is quote-authenticated
// by the replay.
//
// The variable's value is irrelevant here -- host with Secure Boot off still
// measures it, and whether Secure Boot must be on is a policy question
// (RequireSecureBoot).
// What the event proves is that UEFI firmware ran: legacy BIOS/CSM has no EFI
// variables to measure, so its log can never carry one.
//
// PCR 14 is not usable for this:
// it holds the shim MOK state, so it is zero on UEFI host that boots without
// shim (own PK/KEK/db, directly signed systemd-boot or UKI) exactly as it
// is on BIOS.
func UEFIAnchored(facts *BootFacts) bool {
	return facts != nil && facts.SecureBootTrusted && facts.SecureBoot.Found
}

// reports whether the PCR's quoted value is independently authenticated
// by the event log: the quote covers it and the replay reproduces it
func pcrReplayAuthenticated(report *types.AttestationReport, replay *ReplayResult, pcr int) bool {
	if pcr < 0 || pcr >= types.PCRCount {
		return false
	}
	if replay.ExtendCounts[pcr] == 0 {
		return false
	}
	if report.TPM.PCRMask&(1<<uint(pcr)) == 0 {
		return false
	}
	return report.TPM.PCRValues[pcr] == replay.PCRValues[pcr]
}

// derives the policy-facing boot facts from a parsed and replayed
// event log. Fails on malformed or conflicting SecureBoot measurements.
func ExtractBootFacts(report *types.AttestationReport, parsed *ParsedEventLog, replay *ReplayResult) (*BootFacts, error) {
	if report == nil || parsed == nil || replay == nil {
		return nil, errors.New("nil report/event log/replay")
	}

	sb, err := ExtractSecureBootState(parsed)
	if err != nil {
		return nil, err
	}

	return &BootFacts{
		SecureBoot:        sb,
		SecureBootTrusted: pcrReplayAuthenticated(report, replay, 7),
		Cmdlines:          ExtractKernelCmdlines(parsed),
		CmdlineTrusted:    pcrReplayAuthenticated(report, replay, 8),
		PCR8Quoted:        report.TPM.PCRMask&(1<<8) != 0,
		PCR8Reported:      report.TPM.PCRValues[8],
		PCR8EventsSeen:    replay.ExtendCounts[8] > 0,
	}, nil
}

// enforces the cmdline parameter policy against the measured kernel
// command line. GRUB-only in v1: a host whose TPM-quoted PCR 8 is zero
// and whose log carries no PCR 8 measurement never ran a PCR 8-measuring
// bootloader (systemd-boot/UKI measure the cmdline into PCR 12), so the
// check is skipped there. A non-zero quoted PCR 8 without a measured
// cmdline means the log was truncated: the TPM proves something was
// measured, so reject.
func verifyCmdlinePolicy(policy *PCRPolicy, facts *BootFacts) error {
	if facts == nil {
		return errors.New("cmdline policy requires event-log boot facts")
	}

	// the zero-PCR8 skip below is only sound when the zero value is
	// TPM-attested, not agent-asserted
	if !facts.PCR8Quoted {
		return errors.New("cmdline policy: PCR 8 not covered by quote")
	}

	var zero [types.HashSize]byte
	if facts.PCR8Reported == zero && !facts.PCR8EventsSeen && len(facts.Cmdlines) == 0 {
		slog.Info("cmdline policy: PCR 8 is zero with no measured cmdline; skipping (non-GRUB bootloader)")
		return nil
	}

	if !facts.CmdlineTrusted {
		return errors.New("cmdline policy: kernel cmdline measurement not authenticated by quote")
	}
	if len(facts.Cmdlines) == 0 {
		return errors.New("cmdline policy: PCR 8 is non-zero but the log carries no measured kernel cmdline")
	}

	deny := policy.EffectiveCmdlineDeny()
	for _, c := range facts.Cmdlines {
		if hits := MatchCmdlineDeny(c, deny); len(hits) > 0 {
			return fmt.Errorf("kernel cmdline carries denied parameters %v", hits)
		}
	}
	return nil
}
