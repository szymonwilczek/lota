// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - what the PCR14 refusals tell an operator

package verify

import (
	"bytes"
	"strings"
	"testing"
)

// The one line an operator gets when the boot commitment does not derive has
// to carry facts. A TPM obfuscates resetCount and restartCount per signing key,
// and on a firmware TPM the two words a quote carries are not the counters
// TPM2_ReadClock reports at all.
// Neither number enters the derivation, so printing them beside the refusal
// offers evidence that is at best unrelated and at worst invented.
func TestVerify_DerivationMismatchNamesNoObfuscatedCounters(t *testing.T) {
	var logs bytes.Buffer

	v := repinVerifierWithLog(t, &logs)
	const clientID = "derivation-mismatch"

	challenge, err := v.GenerateChallenge(clientID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}

	// a register the reported agent hash cannot produce
	bogus := fixturePCR14()
	bogus[0] ^= 0xFF

	if _, err := v.VerifyReport(clientID, createValidReport(t, clientID,
		challenge.Nonce, bogus)); err == nil {
		t.Fatal("expected refusal: PCR14 derives from nothing the report carries")
	}

	line := logs.String()
	if !strings.Contains(line, "boot-commitment derivation mismatch") {
		t.Fatalf("the refusal an operator reads is not the one logged:\n%s", line)
	}
	for _, word := range []string{"reset_count", "restart_count"} {
		if strings.Contains(line, word) {
			t.Fatalf("the refusal states %s, which binds nothing and is "+
				"obfuscated per signing key:\n%s", word, line)
		}
	}
}
