// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Self-service re-anchor decision

package verify

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// ErrReanchorRateLimited is returned by a store's ArchiveAndReanchor when the
// client's re-anchor interval has not elapsed.
var ErrReanchorRateLimited = errors.New("reanchor: rate limit not elapsed")

// Re-anchor rate limits per assurance tier. The LFA path proves no firmware
// version, so the wider interval is its main barrier against repeated
// downgrade re-anchors.
const (
	ReanchorMinIntervalStrong = 30 * 24 * time.Hour
	ReanchorMinIntervalLFA    = 90 * 24 * time.Hour
)

// reanchorInterval is the minimum spacing between re-anchors for the assurance
// tier, for reanchorDecision and every store's ArchiveAndReanchor alike.
func reanchorInterval(lfa bool) time.Duration {
	if lfa {
		return ReanchorMinIntervalLFA
	}
	return ReanchorMinIntervalStrong
}

// ReanchorVerdict is the outcome of reanchorDecision. The zero value is
// ReanchorEscalate.
type ReanchorVerdict int

const (
	// ReanchorEscalate leaves the decision to the operator.
	ReanchorEscalate ReanchorVerdict = iota
	// ReanchorAllow re-anchors on a forward firmware version.
	ReanchorAllow
	// ReanchorLFA re-anchors with low firmware assurance: no version proof.
	ReanchorLFA
)

// pcr7Variables extracts the Secure Boot variables the firmware measured into
// PCR 7 before its separator (EV_EFI_VARIABLE_DRIVER_CONFIG: PK, KEK, db, dbx,
// SecureBoot) as a map of UnicodeName -> VariableData. An event off its
// digest names nothing.
// EV_EFI_VARIABLE_AUTHORITY is skipped: it records which db entry authorized
// the bootloader and changes on a bootloader update.
func pcr7Variables(parsed *ParsedEventLog) map[string][]byte {
	out := make(map[string][]byte)
	if parsed == nil {
		return out
	}
	events, _ := firmwarePCR7(parsed)
	for _, e := range events {
		if e.EventType != EvEFIVariableDriverConfig {
			continue
		}
		sum := sha256.Sum256(e.EventData)
		if !bytes.Equal(e.Digests[AlgSHA256], sum[:]) {
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

// ReanchorInputs are the facts reanchorDecision weighs. BaselineEventLog is
// the raw log captured with the baseline; CurrentParsed is the current log,
// parsed and quote-verified by the caller.
type ReanchorInputs struct {
	BaselineEventLog    []byte
	CurrentParsed       *ParsedEventLog
	BaselineESRTVersion uint32
	CurrentESRT         *types.ESRTInfo
	ESRTCapable         bool
	LastReanchorAt      time.Time
	Now                 time.Time
}

// reanchorDecision lets boot-baseline drift re-anchor only when it preserves
// the Secure Boot root of trust: PK, KEK, db and SecureBoot byte-identical,
// dbx only appended to, and no firmware rollback. A forward ESRT version is
// the strong path; an unchanged version or a never-present ESRT is LFA.
// An ESRT that disappeared escalates, as does everything else.
func reanchorDecision(in ReanchorInputs) (verdict ReanchorVerdict, reason string) {
	if len(in.BaselineEventLog) == 0 {
		return ReanchorEscalate, "no baseline event log on record (operator re-baseline required)"
	}
	if in.CurrentParsed == nil {
		return ReanchorEscalate, "current event log unavailable"
	}

	// cheap checks first, so a client cannot force the baseline parse and
	// PCR 7 diff on every drift report
	if in.CurrentESRT != nil && in.CurrentESRT.Present {
		// firmware below its anti-rollback floor escalates on either
		// tier; a zero floor was never declared
		if in.CurrentESRT.LowestSupported > 0 &&
			in.CurrentESRT.FWVersion < in.CurrentESRT.LowestSupported {
			return ReanchorEscalate, "firmware version below vendor anti-rollback floor"
		}
		switch {
		case in.CurrentESRT.FWVersion > in.BaselineESRTVersion:
			verdict = ReanchorAllow
		case in.CurrentESRT.FWVersion == in.BaselineESRTVersion:
			verdict = ReanchorLFA
		default:
			return ReanchorEscalate, "firmware version rolled back"
		}
	} else {
		// an ESRT that is gone would downgrade to the LFA path
		if in.ESRTCapable {
			return ReanchorEscalate, "ESRT disappeared (was present before)"
		}
		verdict = ReanchorLFA
	}

	interval := reanchorInterval(verdict == ReanchorLFA)
	if !in.LastReanchorAt.IsZero() && in.Now.Sub(in.LastReanchorAt) < interval {
		return ReanchorEscalate, "re-anchor rate limit not elapsed"
	}

	bl, err := ParseEventLog(in.BaselineEventLog)
	if err != nil {
		return ReanchorEscalate, "baseline event log unparseable"
	}
	bv := pcr7Variables(bl)
	cv := pcr7Variables(in.CurrentParsed)

	if sb, ok := cv["SecureBoot"]; !ok || len(sb) == 0 || sb[0] != 1 {
		return ReanchorEscalate, "Secure Boot not enabled in current event log"
	}

	for _, k := range []string{"PK", "KEK", "db", "SecureBoot"} {
		if !bytes.Equal(bv[k], cv[k]) {
			return ReanchorEscalate, "Secure Boot keyset changed (" + k + ")"
		}
	}

	// dbx may only be appended to
	if !bytes.Equal(bv["dbx"], cv["dbx"]) {
		if len(cv["dbx"]) < len(bv["dbx"]) || !bytes.HasPrefix(cv["dbx"], bv["dbx"]) {
			return ReanchorEscalate, "dbx changed in a non-append way"
		}
	}

	// the number of PCR 7 variables must not change
	if len(bv) != len(cv) {
		return ReanchorEscalate, "PCR 7 variable set changed"
	}

	if verdict == ReanchorLFA {
		return ReanchorLFA, "low-firmware-assurance re-anchor (no firmware version proof)"
	}
	return ReanchorAllow, "firmware drift preserves Secure Boot root of trust"
}
