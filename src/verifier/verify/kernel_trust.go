// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Kernel trust from event-log semantics

package verify

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/szymonwilczek/lota/verifier/types"
)

// SecureBootState is the SecureBoot variable the firmware measured into PCR 7.
type SecureBootState struct {
	Found   bool
	Enabled bool
}

// separatorDigest is what firmware extends for the EV_SEPARATOR that ends
// its own PCR 7 measurements.
var separatorDigest = sha256.Sum256([]byte{0, 0, 0, 0})

// firmwarePCR7 returns the PCR 7 events the replay extended before the
// firmware's separator, and false when no separator was extended.
// The separator is found by its digest, which does not cover the event type.
func firmwarePCR7(parsed *ParsedEventLog) ([]*EventLogEntry, bool) {
	var out []*EventLogEntry
	for i := range parsed.Entries {
		e := &parsed.Entries[i]
		if e.PCRIndex != 7 || e.EventType == EvNoAction {
			continue
		}
		d, ok := e.Digests[AlgSHA256]
		if !ok {
			continue
		}
		if bytes.Equal(d, separatorDigest[:]) {
			return out, true
		}
		out = append(out, e)
	}
	return nil, false
}

// ExtractSecureBootState reads the EFI global SecureBoot variable the
// firmware measured into PCR 7 before its separator, whatever type the log
// gives the event. Enabled means a one-byte value of 0x01.
// A log with no separator reports not-found. A SecureBoot measurement off
// its digest, malformed or conflicting is an error, so the caller fails
// closed.
func ExtractSecureBootState(parsed *ParsedEventLog) (SecureBootState, error) {
	var st SecureBootState
	if parsed == nil {
		return st, errors.New("nil event log")
	}

	events, ok := firmwarePCR7(parsed)
	if !ok {
		return st, nil
	}
	for _, e := range events {
		v, err := parseUEFIVariableData(e.EventData)
		if err != nil {
			if e.EventType == EvEFIVariableDriverConfig {
				return SecureBootState{}, fmt.Errorf("malformed UEFI variable event on PCR 7: %w", err)
			}
			continue
		}
		if v.VariableName != efiGlobalVariableGUID || v.UnicodeName != "SecureBoot" {
			continue
		}
		sum := sha256.Sum256(e.EventData)
		if !bytes.Equal(e.Digests[AlgSHA256], sum[:]) {
			return SecureBootState{}, errors.New("SecureBoot measurement does not match its digest")
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

// ExtractKernelCmdlines returns the kernel command lines, image path dropped,
// in the PCR 8 EV_IPL events whose digest covers their text, and the number
// of PCR 8 EV_IPL events whose digest does not. The log does not say which
// of the lines booted.
func ExtractKernelCmdlines(parsed *ParsedEventLog) (lines []string, unbound int) {
	if parsed == nil {
		return nil, 0
	}

	add := func(line string) {
		for _, l := range lines {
			if l == line {
				return
			}
		}
		lines = append(lines, line)
	}

	for i := range parsed.Entries {
		e := &parsed.Entries[i]
		if e.PCRIndex != 8 || e.EventType != EvIPL {
			continue
		}
		s, covered, ok := boundIPLText(e)
		if !ok {
			unbound++
			continue
		}

		if rest, ok := strings.CutPrefix(s, kernelCmdlinePrefix); ok {
			add(stripImagePathToken(rest))
		}
		if rest, ok := strings.CutPrefix(s, grubCmdPrefix); ok {
			if line, ok := linuxCommandArgs(rest); ok {
				add(line)
			}
		}
		if line, ok := linuxCommandArgs(covered); ok {
			add(line)
		}
		if fields := strings.Fields(covered); len(fields) > 0 && namesKernelImage(fields[0]) {
			add(stripImagePathToken(covered))
		}
	}
	return lines, unbound
}

// boundIPLText returns the event text and the part after its label, once the
// SHA-256 digest is shown to cover it. GRUB hashes the text after "label: "
// without its NUL; a whole-event digest covers the label too.
func boundIPLText(e *EventLogEntry) (text, covered string, ok bool) {
	digest := e.Digests[AlgSHA256]
	text = parseIPLEventString(e.EventData)
	_, rest, labelled := strings.Cut(text, ": ")
	if !labelled {
		rest = text
	}
	for _, c := range []string{string(e.EventData), text, rest} {
		if sum := sha256.Sum256([]byte(c)); bytes.Equal(digest, sum[:]) {
			return text, rest, true
		}
	}
	return "", "", false
}

// parameters of a GRUB linux command, image path dropped
func linuxCommandArgs(cmd string) (string, bool) {
	fields := strings.Fields(cmd)
	if len(fields) < 2 {
		return "", false
	}
	switch fields[0] {
	case "linux", "linuxefi", "linux16":
		return strings.Join(fields[2:], " "), true
	}
	return "", false
}

func stripImagePathToken(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	return ""
}

// builtinCmdlineDeny is the kernel parameter denylist. Rule forms:
//
//	"param"   bare flag or any valued form
//	"param="  any value
//	"param=v" exact key=value pair
var builtinCmdlineDeny = []string{
	"init=",
	"rdinit=",
	"rd.break",
	"lockdown=none",
	"module.sig_enforce=0",
	"selinux=0",
	"enforcing=0",
	"apparmor=0",
	"security=none",
	"systemd.debug_shell",
	"kgdboc=",
}

// the kernel reads '-' and '_' in parameter names as one
func normalizeParamKey(k string) string {
	return strings.ReplaceAll(k, "-", "_")
}

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

// MatchCmdlineDeny returns the deny rules matched by a parameter on cmdline.
// Tokens split on whitespace alone, so a denied key inside a quoted value
// matches too.
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

// KernelImage is the bootloader's measurement of the kernel it loaded,
// taken from the event log.
type KernelImage struct {
	Found  bool
	Path   string // as the bootloader named it, ie (hd0,gpt4)/vmlinuz-...
	Digest []byte
}

// last path element of a measured kernel image starts with one of these
var kernelImagePrefixes = []string{"vmlinuz", "kernel", "bzImage"}

func namesKernelImage(path string) bool {
	base := path
	if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
		base = base[i+1:]
	}
	for _, p := range kernelImagePrefixes {
		if strings.HasPrefix(base, p) {
			return true
		}
	}
	return false
}

// ExtractKernelImageDigest returns the kernel image digest from the PCR 9
// EV_IPL events.
// Found is false when no image is measured. A log naming two different images
// is refused: it does not say which one booted.
func ExtractKernelImageDigest(parsed *ParsedEventLog) (KernelImage, error) {
	var out KernelImage
	if parsed == nil {
		return out, errors.New("nil event log")
	}

	for _, e := range parsed.Entries {
		if e.PCRIndex != 9 || e.EventType != EvIPL {
			continue
		}
		path := parseIPLEventString(e.EventData)
		if !namesKernelImage(path) {
			continue
		}
		digest, ok := e.Digests[AlgSHA256]
		if !ok || len(digest) != types.HashSize {
			return KernelImage{}, fmt.Errorf(
				"kernel image %q carries no SHA-256 measurement", path)
		}

		if out.Found {
			if out.Path == path && bytes.Equal(out.Digest, digest) {
				continue
			}
			return KernelImage{}, fmt.Errorf(
				"event log measures two different kernel images: %q and %q",
				out.Path, path)
		}
		out = KernelImage{
			Found:  true,
			Path:   path,
			Digest: append([]byte(nil), digest...),
		}
	}

	return out, nil
}

// RecordedKernelHash returns the kernel digest the verifier records: the image
// digest when PCR 9 is quoted and replays, the reported register otherwise.
func RecordedKernelHash(report *types.AttestationReport, facts *BootFacts) [types.HashSize]byte {
	var out [types.HashSize]byte
	if facts != nil && facts.KernelImageTrusted && facts.KernelImage.Found {
		copy(out[:], facts.KernelImage.Digest)
		return out
	}
	if report == nil {
		return out
	}
	return report.System.KernelHash
}

// BootFacts carries the boot state the policy gates read from the event log.
// A *Trusted field is set when the quote covers its PCR and the replay
// extended it to the quoted value.
type BootFacts struct {
	SecureBoot        SecureBootState
	SecureBootTrusted bool // PCR 7 quoted + replay-consistent

	Cmdlines       []string
	CmdlineUnbound int  // PCR 8 events whose text the digest does not cover
	CmdlineTrusted bool // PCR 8 quoted + replay-consistent
	PCR8Quoted     bool
	PCR8Reported   [types.HashSize]byte
	PCR8EventsSeen bool

	// a log naming two kernels leaves it unset
	KernelImage        KernelImage
	KernelImageTrusted bool // PCR 9 quoted + replay-consistent

	// Parsed is the log the facts came from, set by VerifyEventLogWithPolicy.
	Parsed *ParsedEventLog
}

// SecureBootAnchored reports whether a trusted PCR 7 replay carries the
// SecureBoot variable enabled.
func SecureBootAnchored(facts *BootFacts) bool {
	return facts != nil && facts.SecureBootTrusted &&
		facts.SecureBoot.Found && facts.SecureBoot.Enabled
}

// UEFIAnchored reports whether a trusted PCR 7 replay carries the SecureBoot
// variable, whatever its value.
func UEFIAnchored(facts *BootFacts) bool {
	return facts != nil && facts.SecureBootTrusted && facts.SecureBoot.Found
}

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

// ExtractBootFacts derives BootFacts from a parsed and replayed event log.
// It fails on a SecureBoot measurement ExtractSecureBootState refuses.
func ExtractBootFacts(report *types.AttestationReport, parsed *ParsedEventLog, replay *ReplayResult) (*BootFacts, error) {
	if report == nil || parsed == nil || replay == nil {
		return nil, errors.New("nil report/event log/replay")
	}

	sb, err := ExtractSecureBootState(parsed)
	if err != nil {
		return nil, err
	}

	img, err := ExtractKernelImageDigest(parsed)
	if err != nil {
		slog.Warn("kernel image measurement unusable", "error", err)
		img = KernelImage{}
	}

	cmdlines, unbound := ExtractKernelCmdlines(parsed)

	return &BootFacts{
		SecureBoot:         sb,
		SecureBootTrusted:  pcrReplayAuthenticated(report, replay, 7),
		Cmdlines:           cmdlines,
		CmdlineUnbound:     unbound,
		CmdlineTrusted:     pcrReplayAuthenticated(report, replay, 8),
		PCR8Quoted:         report.TPM.PCRMask&(1<<8) != 0,
		PCR8Reported:       report.TPM.PCRValues[8],
		PCR8EventsSeen:     replay.ExtendCounts[8] > 0,
		KernelImage:        img,
		KernelImageTrusted: pcrReplayAuthenticated(report, replay, 9),
	}, nil
}

// verifyCmdlinePolicy refuses a measured command line that carries a denied
// parameter. A quoted zero PCR 8 the log never extends skips the check;
// any other host needs a trusted PCR 8, covered events and a command line.
func verifyCmdlinePolicy(policy *PCRPolicy, facts *BootFacts) error {
	if facts == nil {
		return errors.New("cmdline policy requires event-log boot facts")
	}

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
	if facts.CmdlineUnbound > 0 {
		return fmt.Errorf("cmdline policy: %d PCR 8 events carry text their digest does not cover",
			facts.CmdlineUnbound)
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
