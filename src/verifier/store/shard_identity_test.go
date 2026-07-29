// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package store

import "testing"

// fingerprint must separate every list that would route differently.
// Order is part of the routing, so a reordering is a different set,
// and the length prefixes must stop two lists from encoding to the same bytes.
func TestShardSetFingerprintDistinguishesLists(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
	}{
		{"reordered", []string{"aa", "bb"}, []string{"bb", "aa"}},
		{"different member", []string{"aa", "bb"}, []string{"aa", "cc"}},
		{"extra shard", []string{"aa", "bb"}, []string{"aa", "bb", "cc"}},
		{"regrouped without length prefixes", []string{"ab", "c"}, []string{"a", "bc"}},
		{"one vs two", []string{"aa"}, []string{"aa", "aa"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if ShardSetFingerprint(tc.a) == ShardSetFingerprint(tc.b) {
				t.Errorf("%v and %v share a fingerprint", tc.a, tc.b)
			}
		})
	}

	// same list must reproduce, or every restart would look like a change
	ids := []string{"deadbeef", "cafebabe", "f00dface"}
	first := ShardSetFingerprint(ids)
	if again := ShardSetFingerprint(ids); again != first {
		t.Errorf("fingerprint is not stable: %s then %s", first, again)
	}
}

func TestFirstDuplicate(t *testing.T) {
	if _, ok := firstDuplicate([]string{"a", "b", "c"}); ok {
		t.Error("distinct identities reported as duplicated")
	}
	got, ok := firstDuplicate([]string{"a", "b", "a"})
	if !ok || got != "a" {
		t.Errorf("firstDuplicate = %q, %v; want \"a\", true", got, ok)
	}
}
