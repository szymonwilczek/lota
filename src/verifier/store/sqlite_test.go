// SPDX-License-Identifier: MIT
// LOTA Verifier - SQLite AIK Store Tests
//
// Tests for SQLiteAIKStore implementing the AIKStore interface.
// Verifies TOFU registration, hardware ID binding, key persistence,
// and all security invariants match the FileStore/MemoryStore behavior.

package store

import (
	"fmt"
	"testing"
	"time"
)

// helper to create an in-memory SQLite AIK store for testing
func createTestSQLiteAIKStore(t *testing.T) (*SQLiteAIKStore, func()) {
	t.Helper()

	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}

	store := NewSQLiteAIKStore(db)
	cleanup := func() { db.Close() }

	return store, cleanup
}

func TestSQLiteAIK_RegisterAndGet(t *testing.T) {
	t.Log("TEST: SQLite AIK register and retrieve")

	store, cleanup := createTestSQLiteAIKStore(t)
	defer cleanup()

	key := generateTestKey(t)

	// should not exist initially
	_, err := store.GetAIK("client1")
	if err == nil {
		t.Error("Expected error for non-existent client")
	}

	// register
	if err := store.RegisterAIK("client1", &key.PublicKey); err != nil {
		t.Fatalf("RegisterAIK failed: %v", err)
	}

	// retrieve
	gotKey, err := store.GetAIK("client1")
	if err != nil {
		t.Fatalf("GetAIK failed: %v", err)
	}

	if !publicKeysEqual(gotKey, &key.PublicKey) {
		t.Error("Retrieved key does not match registered key")
	}

	t.Log("✓ SQLite AIK register and retrieve works")
}

func TestSQLiteAIK_DuplicateSameKey(t *testing.T) {
	t.Log("TEST: SQLite AIK duplicate registration with same key (idempotent)")

	store, cleanup := createTestSQLiteAIKStore(t)
	defer cleanup()

	key := generateTestKey(t)

	if err := store.RegisterAIK("client1", &key.PublicKey); err != nil {
		t.Fatalf("First RegisterAIK failed: %v", err)
	}

	// same key should succeed (no-op)
	if err := store.RegisterAIK("client1", &key.PublicKey); err != nil {
		t.Errorf("Re-registering same key should succeed: %v", err)
	}

	t.Log("✓ Duplicate registration with same key is idempotent")
}

func TestSQLiteAIK_DuplicateDifferentKey(t *testing.T) {
	t.Log("SECURITY TEST: SQLite AIK rejects different key for same client")

	store, cleanup := createTestSQLiteAIKStore(t)
	defer cleanup()

	key1 := generateTestKey(t)
	key2 := generateTestKey(t)

	if err := store.RegisterAIK("client1", &key1.PublicKey); err != nil {
		t.Fatalf("First RegisterAIK failed: %v", err)
	}

	if err := store.RegisterAIK("client1", &key2.PublicKey); err == nil {
		t.Error("SECURITY: Accepted different key for existing client!")
	}

	t.Log("✓ TOFU invariant enforced: different key rejected")
}

func TestSQLiteAIK_ListClients(t *testing.T) {
	t.Log("TEST: SQLite AIK list clients")

	store, cleanup := createTestSQLiteAIKStore(t)
	defer cleanup()

	key1 := generateTestKey(t)
	key2 := generateTestKey(t)
	key3 := generateTestKey(t)

	store.RegisterAIK("alpha", &key1.PublicKey)
	store.RegisterAIK("beta", &key2.PublicKey)
	store.RegisterAIK("gamma", &key3.PublicKey)

	clients := store.ListClients()
	if len(clients) != 3 {
		t.Errorf("Expected 3 clients, got %d", len(clients))
	}

	// should be ordered
	if clients[0] != "alpha" || clients[1] != "beta" || clients[2] != "gamma" {
		t.Errorf("Clients not ordered: %v", clients)
	}

	t.Log("✓ ListClients returns ordered client IDs")
}

func TestSQLiteAIK_HardwareID(t *testing.T) {
	t.Log("TEST: SQLite AIK hardware ID registration")

	store, cleanup := createTestSQLiteAIKStore(t)
	defer cleanup()

	key := generateTestKey(t)
	store.RegisterAIK("hw-client", &key.PublicKey)

	hwid := [32]byte{0xDE, 0xAD, 0xBE, 0xEF}

	// register hardware ID
	if err := store.RegisterHardwareID("hw-client", hwid); err != nil {
		t.Fatalf("RegisterHardwareID failed: %v", err)
	}

	// retrieve
	got, err := store.GetHardwareID("hw-client")
	if err != nil {
		t.Fatalf("GetHardwareID failed: %v", err)
	}
	if got != hwid {
		t.Error("Hardware ID mismatch")
	}

	// same ID should succeed
	if err := store.RegisterHardwareID("hw-client", hwid); err != nil {
		t.Errorf("Re-registering same HWID should succeed: %v", err)
	}

	t.Log("✓ Hardware ID registration and retrieval works")
}

func TestSQLiteAIK_HardwareIDMismatch(t *testing.T) {
	t.Log("SECURITY TEST: SQLite AIK hardware ID mismatch detection")

	store, cleanup := createTestSQLiteAIKStore(t)
	defer cleanup()

	key := generateTestKey(t)
	store.RegisterAIK("clone-client", &key.PublicKey)

	hwid1 := [32]byte{0x01}
	hwid2 := [32]byte{0x02}

	store.RegisterHardwareID("clone-client", hwid1)

	err := store.RegisterHardwareID("clone-client", hwid2)
	if err != ErrHardwareIDMismatch {
		t.Errorf("Expected ErrHardwareIDMismatch, got: %v", err)
	}

	t.Log("✓ Hardware ID mismatch correctly detected (anti-cloning)")
}

func TestSQLiteAIK_HardwareIDNotFound(t *testing.T) {
	t.Log("TEST: SQLite AIK hardware ID not found")

	store, cleanup := createTestSQLiteAIKStore(t)
	defer cleanup()

	key := generateTestKey(t)
	store.RegisterAIK("no-hwid-client", &key.PublicKey)

	_, err := store.GetHardwareID("no-hwid-client")
	if err != ErrHardwareIDNotFound {
		t.Errorf("Expected ErrHardwareIDNotFound, got: %v", err)
	}

	t.Log("✓ No hardware ID returns proper error")
}

func TestSQLiteAIK_HardwareIDNoClient(t *testing.T) {
	t.Log("TEST: SQLite AIK hardware ID for non-existent client")

	store, cleanup := createTestSQLiteAIKStore(t)
	defer cleanup()

	hwid := [32]byte{0xFF}
	err := store.RegisterHardwareID("nonexistent", hwid)
	if err == nil {
		t.Error("Expected error for non-existent client")
	}

	t.Log("✓ Hardware ID registration requires existing client")
}

func TestSQLiteAIK_Persistence(t *testing.T) {
	t.Log("CRITICAL TEST: SQLite AIK persistence across store instances")
	t.Log("Simulates verifier restart with same database")

	db, err := OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	defer db.Close()

	key := generateTestKey(t)
	hwid := [32]byte{0xCA, 0xFE}

	// first store instance
	store1 := NewSQLiteAIKStore(db)
	store1.RegisterAIK("persist-client", &key.PublicKey)
	store1.RegisterHardwareID("persist-client", hwid)

	// second store instance (simulates restart)
	store2 := NewSQLiteAIKStore(db)

	gotKey, err := store2.GetAIK("persist-client")
	if err != nil {
		t.Fatalf("GetAIK from second instance failed: %v", err)
	}
	if !publicKeysEqual(gotKey, &key.PublicKey) {
		t.Error("Key not persisted correctly")
	}

	gotHWID, err := store2.GetHardwareID("persist-client")
	if err != nil {
		t.Fatalf("GetHardwareID from second instance failed: %v", err)
	}
	if gotHWID != hwid {
		t.Error("Hardware ID not persisted correctly")
	}

	t.Log("✓ AIK and hardware ID persist across store instances")
}

func TestSQLiteAIK_RegisterWithCert(t *testing.T) {
	t.Log("TEST: SQLite AIK RegisterAIKWithCert falls back to TOFU")

	store, cleanup := createTestSQLiteAIKStore(t)
	defer cleanup()

	key := generateTestKey(t)

	// should succeed (TOFU fallback)
	if err := store.RegisterAIKWithCert("cert-client", &key.PublicKey, nil, nil); err != nil {
		t.Errorf("RegisterAIKWithCert should succeed: %v", err)
	}

	gotKey, err := store.GetAIK("cert-client")
	if err != nil {
		t.Fatalf("GetAIK failed: %v", err)
	}
	if !publicKeysEqual(gotKey, &key.PublicKey) {
		t.Error("Key mismatch after RegisterAIKWithCert")
	}

	t.Log("✓ RegisterAIKWithCert delegates to TOFU registration")
}

func TestSQLiteAIK_MultipleClients(t *testing.T) {
	t.Log("TEST: SQLite AIK multiple independent clients")

	store, cleanup := createTestSQLiteAIKStore(t)
	defer cleanup()

	const numClients = 50

	for i := 0; i < numClients; i++ {
		clientID := fmt.Sprintf("client-%03d", i)
		key := generateTestKey(t)
		hwid := [32]byte{byte(i)}

		if err := store.RegisterAIK(clientID, &key.PublicKey); err != nil {
			t.Fatalf("RegisterAIK(%s) failed: %v", clientID, err)
		}
		if err := store.RegisterHardwareID(clientID, hwid); err != nil {
			t.Fatalf("RegisterHardwareID(%s) failed: %v", clientID, err)
		}
	}

	clients := store.ListClients()
	if len(clients) != numClients {
		t.Errorf("Expected %d clients, got %d", numClients, len(clients))
	}

	t.Logf("✓ %d independent clients registered and listed", numClients)
}

func TestSQLiteAIK_GetRegisteredAt(t *testing.T) {
	t.Log("TEST: SQLite AIK registration timestamp")

	store, cleanup := createTestSQLiteAIKStore(t)
	defer cleanup()

	key := generateTestKey(t)

	// should fail for unknown client
	_, err := store.GetRegisteredAt("unknown")
	if err == nil {
		t.Error("Expected error for non-existent client")
	}

	store.RegisterAIK("ts-client", &key.PublicKey)

	regTime, err := store.GetRegisteredAt("ts-client")
	if err != nil {
		t.Fatalf("GetRegisteredAt failed: %v", err)
	}

	if regTime.IsZero() {
		t.Error("Registration time should not be zero")
	}

	// should be recent (within last 10 seconds)
	if time.Since(regTime) > 10*time.Second {
		t.Errorf("Registration time too old: %v", regTime)
	}

	t.Log("✓ SQLite created_at timestamp is populated and readable")
}

func TestSQLiteAIK_RotateAIK(t *testing.T) {
	t.Log("SECURITY TEST: SQLite AIK key rotation")

	store, cleanup := createTestSQLiteAIKStore(t)
	defer cleanup()

	key1 := generateTestKey(t)
	key2 := generateTestKey(t)

	store.RegisterAIK("rotate-client", &key1.PublicKey)

	// different key via RegisterAIK should fail
	if err := store.RegisterAIK("rotate-client", &key2.PublicKey); err == nil {
		t.Error("SECURITY: RegisterAIK accepted different key")
	}

	// RotateAIK should succeed
	if err := store.RotateAIK("rotate-client", &key2.PublicKey); err != nil {
		t.Fatalf("RotateAIK failed: %v", err)
	}

	// should now return new key
	gotKey, err := store.GetAIK("rotate-client")
	if err != nil {
		t.Fatalf("GetAIK after rotation failed: %v", err)
	}
	if !publicKeysEqual(gotKey, &key2.PublicKey) {
		t.Error("Rotated key does not match expected key")
	}

	t.Log("✓ RotateAIK replaces key while RegisterAIK enforces TOFU")
}

func TestSQLiteAIK_RotatePreservesHardwareID(t *testing.T) {
	t.Log("CRITICAL TEST: SQLite AIK rotation preserves hardware ID binding")

	store, cleanup := createTestSQLiteAIKStore(t)
	defer cleanup()

	key1 := generateTestKey(t)
	key2 := generateTestKey(t)
	hwid := [32]byte{0xCA, 0xFE, 0xBA, 0xBE}

	store.RegisterAIK("hw-rotate", &key1.PublicKey)
	store.RegisterHardwareID("hw-rotate", hwid)

	// rotate key
	store.RotateAIK("hw-rotate", &key2.PublicKey)

	// hardware ID must still be intact
	gotHWID, err := store.GetHardwareID("hw-rotate")
	if err != nil {
		t.Fatalf("GetHardwareID after rotation failed: %v", err)
	}
	if gotHWID != hwid {
		t.Error("Hardware ID lost after AIK rotation - security binding broken!")
	}

	t.Log("✓ Hardware ID preserved across AIK rotation")
}

func TestSQLiteAIK_RotateUpdatesTimestamp(t *testing.T) {
	t.Log("TEST: SQLite AIK rotation updates created_at timestamp")

	store, cleanup := createTestSQLiteAIKStore(t)
	defer cleanup()

	key1 := generateTestKey(t)
	key2 := generateTestKey(t)

	store.RegisterAIK("ts-rotate", &key1.PublicKey)
	regTime1, _ := store.GetRegisteredAt("ts-rotate")

	// SQLite CURRENT_TIMESTAMP has second-level precision;
	// sub-second sleeps cause flaky timestamp comparisons
	time.Sleep(1100 * time.Millisecond)

	store.RotateAIK("ts-rotate", &key2.PublicKey)
	regTime2, _ := store.GetRegisteredAt("ts-rotate")

	if !regTime2.After(regTime1) {
		t.Errorf("Rotation should update timestamp: before=%v, after=%v", regTime1, regTime2)
	}

	t.Log("✓ Rotation resets registration timestamp")
}

func TestSQLiteAIK_RotateNonexistent(t *testing.T) {
	t.Log("TEST: SQLite AIK rotation of non-existent client fails")

	store, cleanup := createTestSQLiteAIKStore(t)
	defer cleanup()

	key := generateTestKey(t)

	if err := store.RotateAIK("nonexistent", &key.PublicKey); err == nil {
		t.Error("RotateAIK should fail for non-existent client")
	}

	t.Log("✓ RotateAIK correctly rejects non-existent client")
}
