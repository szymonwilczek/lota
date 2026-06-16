// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Self-service re-anchor decision

package verify

import (
	"bytes"
	"errors"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// ErrReanchorRateLimited is returned by a store's ArchiveAndReanchor when the
// per-client re-anchor interval has not elapsed.
// Interval is re-checked inside the write transaction (under the row lock),
// so a burst of concurrent attestations for one client cannot race the cheap-path
// rate-limit gate in reanchorDecision and re-anchor more than once per window.
var ErrReanchorRateLimited = errors.New("reanchor: rate limit not elapsed")

// Re-anchor rate limits per assurance tier.
// Strong path proves a forward firmware version; the LFA path cannot,
// so it is held to a wider interval because the rate limit is then
// the main barrier against repeated downgrade re-anchors.
const (
	ReanchorMinIntervalStrong = 30 * 24 * time.Hour
	ReanchorMinIntervalLFA    = 90 * 24 * time.Hour
)

// reanchorInterval is the minimum spacing between re-anchors for the assurance
// tier.
// LFA path (no firmware version proof) is held to the wider interval because
// the rate limit is then the main barrier against repeated downgrade re-anchors.
// Both reanchorDecision (cheap-path gate) and every store's ArchiveAndReanchor
// (authoritative in-transaction guard) derive the interval here so the two
// cannot drift apart.
func reanchorInterval(lfa bool) time.Duration {
	if lfa {
		return ReanchorMinIntervalLFA
	}
	return ReanchorMinIntervalStrong
}

// ReanchorVerdict is the outcome of the re-anchor discriminator.
// The zero value is Escalate so any unhandled path fails closed to the operator.
type ReanchorVerdict int

const (
	// ReanchorEscalate: self-service refuses; the operator must decide.
	ReanchorEscalate ReanchorVerdict = iota
	// ReanchorAllow: strong path, the device may re-anchor automatically.
	ReanchorAllow
	// ReanchorLFA: low-firmware-assurance re-anchor (no firmware version proof).
	ReanchorLFA
)

func (v ReanchorVerdict) String() string {
	switch v {
	case ReanchorAllow:
		return "allow"
	case ReanchorLFA:
		return "lfa"
	default:
		return "escalate"
	}
}

// pcr7Variables extracts the Secure Boot variables measured into PCR 7
// (EV_EFI_VARIABLE_DRIVER_CONFIG: PK, KEK, db, dbx, SecureBoot) as a map of
// UnicodeName -> VariableData.
// EV_EFI_VARIABLE_AUTHORITY is intentionally skipped:
// it records which db entry authorized the bootloader and changes on a legitimate
// bootloader update, so it is not part of the root of trust the re-anchor must hold constant.
func pcr7Variables(parsed *ParsedEventLog) map[string][]byte {
	out := make(map[string][]byte)
	if parsed == nil {
		return out
	}
	for i := range parsed.Entries {
		e := &parsed.Entries[i]
		if e.PCRIndex != 7 || e.EventType != EvEFIVariableDriverConfig {
			continue
		}
		uv, err := parseUEFIVariableData(e.EventData)
		if err != nil {
			continue
		}
		out[uv.UnicodeName] = uv.VariableData
	}
	return out
}

// ReanchorInputs are the facts the discriminator weighs:
// the event log captured when the baseline was pinned (raw bytes, parsed here once)
// vs the current one (already parsed and quote-verified upstream, reused as-is),
// the firmware versions, the sticky ESRT-capability bit, and the rate-limit clock.
type ReanchorInputs struct {
	BaselineEventLog    []byte
	CurrentParsed       *ParsedEventLog
	BaselineESRTVersion uint32
	CurrentESRT         *types.ESRTInfo
	ESRTCapable         bool
	LastReanchorAt      time.Time
	Now                 time.Time
}

// reanchorDecision implements the discriminator:
// boot-baseline drift may be re-anchored only when it preserves the Secure Boot
// root of trust. Secure Boot keyset (PK, KEK, db, SecureBoot) must be
// byte-identical, dbx may only have grown (append-only revocation), and the
// firmware version must not roll back.
// ESRT presence selects the assurance tier: a forward version is the strong path;
// an unchanged version or a never-present ESRT is LFA.
// ESRT that disappeared after once being present escalates.
// Everything else escalates to the operator.
func reanchorDecision(in ReanchorInputs) (verdict ReanchorVerdict, reason string) {
	// fail-closed: without the baseline event log there is no reference
	// to replay-diff PCR 7 against
	if len(in.BaselineEventLog) == 0 {
		return ReanchorEscalate, "no baseline event log on record (operator re-baseline required)"
	}
	if in.CurrentParsed == nil {
		return ReanchorEscalate, "current event log unavailable"
	}

	// cheap checks first, so a client cannot force the expensive baseline
	// parse + PCR 7 replay-diff on every drift report
	// assurance tier and the anti-rollback / disappeared-ESRT escalations
	// are decided from the ESRT alone, then the rate limit short-circuits
	// before any parsing.
	verdict = ReanchorAllow
	if in.CurrentESRT != nil && in.CurrentESRT.Present {
		switch {
		case in.CurrentESRT.FWVersion > in.BaselineESRTVersion:
			// forward update -> strong, but only when the running version is
			// at or above the vendor's own anti-rollback floor
			// LowestSupported above FWVersion means the firmware reports it is
			// running below the lowest version it claims to accept;
			// that is exactly the rollback the floor exists to catch, so it
			// escalates instead of earning the automatic strong re-anchor.
			// Floor of zero means none was declared.
			if in.CurrentESRT.LowestSupported > 0 &&
				in.CurrentESRT.FWVersion < in.CurrentESRT.LowestSupported {
				return ReanchorEscalate, "firmware version below vendor anti-rollback floor"
			}
			verdict = ReanchorAllow
		case in.CurrentESRT.FWVersion == in.BaselineESRTVersion:
			verdict = ReanchorLFA // unchanged version despite drift (DIY flash)
		default:
			return ReanchorEscalate, "firmware version rolled back"
		}
	} else {
		// no ESRT now:
		// ESRT that was present before and is gone is suspicious
		// (a downgrade to the weaker path);
		// device that never had one falls onto LFA
		if in.ESRTCapable {
			return ReanchorEscalate, "ESRT disappeared (was present before)"
		}
		verdict = ReanchorLFA
	}

	interval := reanchorInterval(verdict == ReanchorLFA)
	if !in.LastReanchorAt.IsZero() && in.Now.Sub(in.LastReanchorAt) < interval {
		return ReanchorEscalate, "re-anchor rate limit not elapsed"
	}

	// expensive checks:
	// current log was already parsed and quote-verified upstream (reused here);
	// only the baseline is parsed, and only once the cheap gates above admitted
	// the report
	bl, err := ParseEventLog(in.BaselineEventLog)
	if err != nil {
		return ReanchorEscalate, "baseline event log unparseable"
	}
	bv := pcr7Variables(bl)
	cv := pcr7Variables(in.CurrentParsed)

	// Secure Boot must still be enabled in the current log
	if sb, ok := cv["SecureBoot"]; !ok || len(sb) == 0 || sb[0] != 1 {
		return ReanchorEscalate, "Secure Boot not enabled in current event log"
	}

	// root of trust must be byte-identical
	for _, k := range []string{"PK", "KEK", "db", "SecureBoot"} {
		if !bytes.Equal(bv[k], cv[k]) {
			return ReanchorEscalate, "Secure Boot keyset changed (" + k + ")"
		}
	}

	// dbx may only grow (append-only revocation)
	// shrink or a non-prefix change is treated as a keyset change and escalates
	if !bytes.Equal(bv["dbx"], cv["dbx"]) {
		if len(cv["dbx"]) < len(bv["dbx"]) || !bytes.HasPrefix(cv["dbx"], bv["dbx"]) {
			return ReanchorEscalate, "dbx changed in a non-append way"
		}
	}

	// no PCR 7 variable may appear or vanish
	if len(bv) != len(cv) {
		return ReanchorEscalate, "PCR 7 variable set changed"
	}

	if verdict == ReanchorLFA {
		return ReanchorLFA, "low-firmware-assurance re-anchor (no firmware version proof)"
	}
	return ReanchorAllow, "firmware drift preserves Secure Boot root of trust"
}
