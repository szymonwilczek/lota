// SPDX-License-Identifier: MIT
// LOTA Verifier - Revocation, Ban, and Audit Log Store Tests
//
// Tests for all RevocationStore, BanStore, and AuditLog
// implementations.

package store

import (
	"testing"
	"time"
)

func testRevocationStore(t *testing.T, s RevocationStore, label string) {
	t.Helper()

	t.Run(label+"/Revoke", func(t *testing.T) {
		err := s.Revoke("client-1", RevocationCheating, "admin@test", "caught cheating")
		if err != nil {
			t.Fatalf("Revoke failed: %v", err)
		}

		entry, revoked := s.IsRevoked("client-1")
		if !revoked {
			t.Fatal("Expected client-1 to be revoked")
		}
		if entry.ClientID != "client-1" {
			t.Errorf("ClientID: got %q, want %q", entry.ClientID, "client-1")
		}
		if entry.Reason != RevocationCheating {
			t.Errorf("Reason: got %q, want %q", entry.Reason, RevocationCheating)
		}
		if entry.RevokedBy != "admin@test" {
			t.Errorf("RevokedBy: got %q, want %q", entry.RevokedBy, "admin@test")
		}
		if entry.Note != "caught cheating" {
			t.Errorf("Note: got %q, want %q", entry.Note, "caught cheating")
		}
		if entry.RevokedAt.IsZero() {
			t.Error("RevokedAt should not be zero")
		}
	})

	t.Run(label+"/AlreadyRevoked", func(t *testing.T) {
		err := s.Revoke("client-1", RevocationAdmin, "admin2", "")
		if err != ErrAlreadyRevoked {
			t.Fatalf("Expected ErrAlreadyRevoked, got %v", err)
		}
	})

	t.Run(label+"/NotRevoked", func(t *testing.T) {
		_, revoked := s.IsRevoked("nonexistent")
		if revoked {
			t.Fatal("Expected nonexistent client to not be revoked")
		}
	})

	t.Run(label+"/Unrevoke", func(t *testing.T) {
		err := s.Unrevoke("client-1")
		if err != nil {
			t.Fatalf("Unrevoke failed: %v", err)
		}

		_, revoked := s.IsRevoked("client-1")
		if revoked {
			t.Fatal("Expected client-1 to be unrevoked")
		}
	})

	t.Run(label+"/UnrevokeNotRevoked", func(t *testing.T) {
		err := s.Unrevoke("never-revoked")
		if err != ErrNotRevoked {
			t.Fatalf("Expected ErrNotRevoked, got %v", err)
		}
	})

	t.Run(label+"/ListRevocations", func(t *testing.T) {
		// revoke multiple
		s.Revoke("list-a", RevocationCheating, "admin", "")
		s.Revoke("list-b", RevocationCompromised, "admin", "")
		s.Revoke("list-c", RevocationAdmin, "admin", "")

		entries := s.ListRevocations()
		if len(entries) < 3 {
			t.Fatalf("Expected at least 3 revocations, got %d", len(entries))
		}

		found := make(map[string]bool)
		for _, e := range entries {
			found[e.ClientID] = true
		}
		for _, id := range []string{"list-a", "list-b", "list-c"} {
			if !found[id] {
				t.Errorf("Missing revocation for %s", id)
			}
		}
	})

	t.Run(label+"/AllReasons", func(t *testing.T) {
		for _, reason := range ValidRevocationReasons {
			id := "reason-" + string(reason)
			err := s.Revoke(id, reason, "test", "")
			if err != nil {
				t.Errorf("Revoke with reason %q failed: %v", reason, err)
			}
			entry, ok := s.IsRevoked(id)
			if !ok {
				t.Errorf("Client %s should be revoked", id)
				continue
			}
			if entry.Reason != reason {
				t.Errorf("Reason mismatch: got %q, want %q", entry.Reason, reason)
			}
		}
	})
}

func TestMemoryRevocationStore(t *testing.T) {
	s := NewMemoryRevocationStore()
	testRevocationStore(t, s, "Memory")
}

func TestSQLiteRevocationStore(t *testing.T) {
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	auditLog := NewSQLiteAuditLog(db)
	s := NewSQLiteRevocationStore(db, auditLog)
	testRevocationStore(t, s, "SQLite")

	// verify audit log was populated
	t.Run("SQLite/AuditTrail", func(t *testing.T) {
		entries := auditLog.Query(0)
		if len(entries) == 0 {
			t.Fatal("Expected audit log entries after revocations")
		}

		hasRevoke := false
		hasUnrevoke := false
		for _, e := range entries {
			if e.Action == "revoke" {
				hasRevoke = true
			}
			if e.Action == "unrevoke" {
				hasUnrevoke = true
			}
		}
		if !hasRevoke {
			t.Error("Missing 'revoke' action in audit log")
		}
		if !hasUnrevoke {
			t.Error("Missing 'unrevoke' action in audit log")
		}
	})
}

func testBanStore(t *testing.T, s BanStore, label string) {
	t.Helper()

	hwid1 := [32]byte{0x01, 0x02, 0x03}
	hwid2 := [32]byte{0xAA, 0xBB, 0xCC}

	t.Run(label+"/BanHardware", func(t *testing.T) {
		err := s.BanHardware(hwid1, RevocationCheating, "admin@test", "hardware ban")
		if err != nil {
			t.Fatalf("BanHardware failed: %v", err)
		}

		entry, banned := s.IsBanned(hwid1)
		if !banned {
			t.Fatal("Expected hwid1 to be banned")
		}
		if entry.HardwareID != hwid1 {
			t.Error("HardwareID mismatch")
		}
		if entry.Reason != RevocationCheating {
			t.Errorf("Reason: got %q, want %q", entry.Reason, RevocationCheating)
		}
		if entry.BannedBy != "admin@test" {
			t.Errorf("BannedBy: got %q, want %q", entry.BannedBy, "admin@test")
		}
		if entry.BannedAt.IsZero() {
			t.Error("BannedAt should not be zero")
		}
	})

	t.Run(label+"/AlreadyBanned", func(t *testing.T) {
		err := s.BanHardware(hwid1, RevocationAdmin, "admin2", "")
		if err != ErrAlreadyBanned {
			t.Fatalf("Expected ErrAlreadyBanned, got %v", err)
		}
	})

	t.Run(label+"/NotBanned", func(t *testing.T) {
		_, banned := s.IsBanned([32]byte{0xFF})
		if banned {
			t.Fatal("Expected unknown hwid to not be banned")
		}
	})

	t.Run(label+"/UnbanHardware", func(t *testing.T) {
		err := s.UnbanHardware(hwid1)
		if err != nil {
			t.Fatalf("UnbanHardware failed: %v", err)
		}

		_, banned := s.IsBanned(hwid1)
		if banned {
			t.Fatal("Expected hwid1 to be unbanned")
		}
	})

	t.Run(label+"/UnbanNotBanned", func(t *testing.T) {
		err := s.UnbanHardware([32]byte{0xDE, 0xAD})
		if err != ErrNotBanned {
			t.Fatalf("Expected ErrNotBanned, got %v", err)
		}
	})

	t.Run(label+"/ListBans", func(t *testing.T) {
		s.BanHardware(hwid1, RevocationCheating, "admin", "")
		s.BanHardware(hwid2, RevocationCompromised, "admin", "")

		entries := s.ListBans()
		if len(entries) < 2 {
			t.Fatalf("Expected at least 2 bans, got %d", len(entries))
		}

		found := make(map[[32]byte]bool)
		for _, e := range entries {
			found[e.HardwareID] = true
		}
		if !found[hwid1] || !found[hwid2] {
			t.Error("Missing bans in list")
		}
	})
}

func TestMemoryBanStore(t *testing.T) {
	s := NewMemoryBanStore()
	testBanStore(t, s, "Memory")
}

func TestSQLiteBanStore(t *testing.T) {
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	auditLog := NewSQLiteAuditLog(db)
	s := NewSQLiteBanStore(db, auditLog)
	testBanStore(t, s, "SQLite")

	// verify audit log was populated
	t.Run("SQLite/AuditTrail", func(t *testing.T) {
		entries := auditLog.Query(0)
		hasBan := false
		hasUnban := false
		for _, e := range entries {
			if e.Action == "ban" {
				hasBan = true
			}
			if e.Action == "unban" {
				hasUnban = true
			}
		}
		if !hasBan {
			t.Error("Missing 'ban' action in audit log")
		}
		if !hasUnban {
			t.Error("Missing 'unban' action in audit log")
		}
	})
}

func testAuditLog(t *testing.T, l AuditLog, label string) {
	t.Helper()

	t.Run(label+"/Log", func(t *testing.T) {
		err := l.Log("revoke", "client-1", "cheating", "admin", "test note")
		if err != nil {
			t.Fatalf("Log failed: %v", err)
		}

		entries := l.Query(1)
		if len(entries) != 1 {
			t.Fatalf("Expected 1 entry, got %d", len(entries))
		}

		e := entries[0]
		if e.Action != "revoke" {
			t.Errorf("Action: got %q, want %q", e.Action, "revoke")
		}
		if e.TargetID != "client-1" {
			t.Errorf("TargetID: got %q, want %q", e.TargetID, "client-1")
		}
		if e.Reason != "cheating" {
			t.Errorf("Reason: got %q, want %q", e.Reason, "cheating")
		}
		if e.Actor != "admin" {
			t.Errorf("Actor: got %q, want %q", e.Actor, "admin")
		}
		if e.Note != "test note" {
			t.Errorf("Note: got %q, want %q", e.Note, "test note")
		}
		if e.Timestamp.IsZero() {
			t.Error("Timestamp should not be zero")
		}
	})

	t.Run(label+"/QueryNewestFirst", func(t *testing.T) {
		l.Log("action-1", "target-1", "", "", "")
		time.Sleep(2 * time.Millisecond) // ensure different timestamps
		l.Log("action-2", "target-2", "", "", "")

		entries := l.Query(2)
		if len(entries) < 2 {
			t.Fatalf("Expected at least 2 entries, got %d", len(entries))
		}

		// newest first: action-2 should be first
		if entries[0].Action != "action-2" {
			t.Errorf("First entry should be newest: got %q, want %q",
				entries[0].Action, "action-2")
		}
	})

	t.Run(label+"/QueryLimit", func(t *testing.T) {
		// enough entries
		for i := 0; i < 5; i++ {
			l.Log("bulk", "target", "", "", "")
		}

		entries := l.Query(3)
		if len(entries) != 3 {
			t.Errorf("Expected 3 entries with limit=3, got %d", len(entries))
		}
	})

	t.Run(label+"/QueryAll", func(t *testing.T) {
		entries := l.Query(0)
		if len(entries) == 0 {
			t.Error("Expected non-empty audit log")
		}
	})
}

func TestMemoryAuditLog(t *testing.T) {
	l := NewMemoryAuditLog()
	testAuditLog(t, l, "Memory")
}

func TestSQLiteAuditLog(t *testing.T) {
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	l := NewSQLiteAuditLog(db)
	testAuditLog(t, l, "SQLite")
}

func TestFormatParseHardwareID(t *testing.T) {
	original := [32]byte{
		0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
		0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
		0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
	}

	hex := FormatHardwareID(original)
	parsed, err := ParseHardwareID(hex)
	if err != nil {
		t.Fatalf("ParseHardwareID failed: %v", err)
	}

	if parsed != original {
		t.Error("Round-trip failed: parsed != original")
	}
}

func TestParseHardwareID_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"too short", "deadbeef"},
		{"too long", "deadbeef0102030405060708090a0b0c0d0e0f101112131415161718191a1b1cFF"},
		{"invalid hex", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseHardwareID(tc.input)
			if err == nil {
				t.Errorf("Expected error for input %q", tc.input)
			}
		})
	}
}

func TestIsValidReason(t *testing.T) {
	valid := []string{"cheating", "compromised", "hardware_change", "admin"}
	for _, reason := range valid {
		if !IsValidReason(reason) {
			t.Errorf("Expected %q to be valid", reason)
		}
	}

	invalid := []string{"", "unknown", "CHEATING", "hacking", "  cheating  "}
	for _, reason := range invalid {
		if IsValidReason(reason) {
			t.Errorf("Expected %q to be invalid", reason)
		}
	}
}

func TestMigrationV2_RevocationsTable(t *testing.T) {
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	// insert and query
	now := time.Now().UTC()
	_, err = db.Exec(
		"INSERT INTO revocations (client_id, reason, revoked_at, revoked_by, note) VALUES (?, ?, ?, ?, ?)",
		"test-client", "cheating", now, "admin", "test note",
	)
	if err != nil {
		t.Fatalf("Insert into revocations failed: %v", err)
	}

	// duplicate PK should fail
	_, err = db.Exec(
		"INSERT INTO revocations (client_id, reason, revoked_at) VALUES (?, ?, ?)",
		"test-client", "admin", now,
	)
	if err == nil {
		t.Fatal("Expected PRIMARY KEY violation")
	}

	t.Log("✓ revocations table with PK constraint works correctly")
}

func TestMigrationV2_HardwareBansTable(t *testing.T) {
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	// valid 32-byte hardware ID
	hwid := make([]byte, 32)
	hwid[0] = 0xDE
	hwid[1] = 0xAD

	_, err = db.Exec(
		"INSERT INTO hardware_bans (hardware_id, reason, banned_at, banned_by, note) VALUES (?, ?, ?, ?, ?)",
		hwid, "cheating", time.Now().UTC(), "admin", "",
	)
	if err != nil {
		t.Fatalf("Insert into hardware_bans failed: %v", err)
	}

	// wrong-length hardware ID should fail CHECK constraint
	_, err = db.Exec(
		"INSERT INTO hardware_bans (hardware_id, reason, banned_at) VALUES (?, ?, ?)",
		[]byte("short"), "admin", time.Now().UTC(),
	)
	if err == nil {
		t.Fatal("SECURITY: Accepted hardware_id with wrong length!")
	}

	t.Log("✓ hardware_bans table with CHECK(length=32) works correctly")
}

func TestMigrationV2_AuditLogTable(t *testing.T) {
	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	// insert multiple entries
	for i := 0; i < 5; i++ {
		_, err = db.Exec(
			"INSERT INTO audit_log (timestamp, action, target_id, reason, actor, note) VALUES (?, ?, ?, ?, ?, ?)",
			time.Now().UTC(), "test", "target", "reason", "actor", "note",
		)
		if err != nil {
			t.Fatalf("Insert into audit_log failed: %v", err)
		}
	}

	// verify autoincrement
	var maxID int64
	db.QueryRow("SELECT MAX(id) FROM audit_log").Scan(&maxID)
	if maxID != 5 {
		t.Errorf("Expected max id 5, got %d", maxID)
	}

	// verify indexes exist
	for _, idx := range []string{"idx_audit_log_timestamp", "idx_audit_log_target"} {
		var name string
		err := db.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='index' AND name=?", idx,
		).Scan(&name)
		if err != nil {
			t.Errorf("Index %s not found: %v", idx, err)
		}
	}

	t.Log("✓ audit_log table with AUTOINCREMENT and indexes works correctly")
}

func TestSQLiteRevocationStore_Persistence(t *testing.T) {
	t.Log("SECURITY TEST: Revocations survive database reopen")

	dir := t.TempDir()
	dbPath := dir + "/revoke-persist.db"

	// first open: revoke a client
	db1, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	s1 := NewSQLiteRevocationStore(db1, nil)
	s1.Revoke("persist-client", RevocationCheating, "admin", "persist test")
	db1.Close()

	// second open: revocation must persist
	db2, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer db2.Close()
	s2 := NewSQLiteRevocationStore(db2, nil)

	entry, revoked := s2.IsRevoked("persist-client")
	if !revoked {
		t.Fatal("SECURITY: Revocation lost after database reopen!")
	}
	if entry.Reason != RevocationCheating {
		t.Errorf("Reason after reopen: got %q, want %q", entry.Reason, RevocationCheating)
	}

	t.Log("✓ Revocation persists across database reopens")
}

func TestSQLiteBanStore_Persistence(t *testing.T) {
	t.Log("SECURITY TEST: Hardware bans survive database reopen")

	dir := t.TempDir()
	dbPath := dir + "/ban-persist.db"

	hwid := [32]byte{0xBA, 0xD0}

	// first open: ban hardware
	db1, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	s1 := NewSQLiteBanStore(db1, nil)
	s1.BanHardware(hwid, RevocationCheating, "admin", "ban persist test")
	db1.Close()

	// second open: ban must persist
	db2, err := OpenDB(dbPath)
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer db2.Close()
	s2 := NewSQLiteBanStore(db2, nil)

	entry, banned := s2.IsBanned(hwid)
	if !banned {
		t.Fatal("SECURITY: Hardware ban lost after database reopen!")
	}
	if entry.Reason != RevocationCheating {
		t.Errorf("Reason after reopen: got %q, want %q", entry.Reason, RevocationCheating)
	}

	t.Log("✓ Hardware ban persists across database reopens")
}
