// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package verify

import (
	"testing"
	"time"

	"github.com/szymonwilczek/lota/verifier/types"
)

// FuzzReanchorDecision feeds arbitrary baseline and current event-log bytes
// (plus an ESRT) to the re-anchor discriminator.
// reanchorDecision parses untrusted event logs from a re-anchoring client,
// so it must never panic and must always return one of the three known verdicts.
func FuzzReanchorDecision(f *testing.F) {
	base := pcr7Log(baseVars())
	f.Add(base, base, uint32(700), true, true)
	f.Add([]byte(nil), base, uint32(0), false, false)
	f.Add(base, pcr7Log(varsWith("dbx", []byte("dbx0+x"))), uint32(800), true, true)
	f.Add([]byte("garbage"), []byte("more garbage"), uint32(1), true, false)

	f.Fuzz(func(t *testing.T, baseline, current []byte, esrtVer uint32,
		esrtPresent, capable bool,
	) {
		var cur *types.ESRTInfo
		if esrtPresent {
			cur = &types.ESRTInfo{Present: true, FWVersion: esrtVer}
		}
		// current is parsed upstream in production;
		// malformed log yields a nil parse here, which the decision
		// must also handle without panic
		parsedCur, _ := ParseEventLog(current)
		v, _ := reanchorDecision(ReanchorInputs{
			BaselineEventLog:    baseline,
			CurrentParsed:       parsedCur,
			BaselineESRTVersion: esrtVer,
			CurrentESRT:         cur,
			ESRTCapable:         capable,
			Now:                 time.Now(),
		})
		if v != ReanchorEscalate && v != ReanchorAllow && v != ReanchorLFA {
			t.Fatalf("unknown verdict %d", v)
		}
	})
}
