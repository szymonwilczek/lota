// SPDX-License-Identifier: MIT
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
	"strings"
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
