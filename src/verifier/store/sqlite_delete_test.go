// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package store

import (
	"errors"
	"testing"
)

// Every persistent AIK registry implements ClientDeleter;
// otherwise CertificateStore reports ErrDeleteUnsupported and the API
// delete answers 500.
func TestEveryPersistentAIKRegistryCanRemoveAClient(t *testing.T) {
	dir := t.TempDir()

	db, err := OpenDB(dir + "/aik.sqlite")
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()

	fileStore, err := NewFileStore(dir + "/file")
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	registries := map[string]any{
		"sqlite":   NewSQLiteAIKStore(db),
		"file":     fileStore,
		"memory":   NewMemoryStore(),
		"postgres": (*PostgresAIKStore)(nil),
	}

	for name, reg := range registries {
		t.Run(name, func(t *testing.T) {
			if _, ok := reg.(ClientDeleter); !ok {
				t.Fatalf("the %s registry cannot remove a client, so the operator's delete answers 500 on it", name)
			}
		})
	}
}

// SQLite delete removes AIK, hardware ID and client row;
// a repeat delete reports ErrAIKNotFound.
func TestSQLiteAIKDeleteRemovesTheClient(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(dir + "/aik.sqlite")
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	defer db.Close()

	s := NewSQLiteAIKStore(db)
	deleter, ok := any(s).(ClientDeleter)
	if !ok {
		t.Skip("registry cannot delete; covered by the parity test above")
	}

	key := generateTestKey(t)
	if err := s.RegisterAIK("host-0001", &key.PublicKey); err != nil {
		t.Fatalf("RegisterAIK: %v", err)
	}
	var hwID [32]byte
	hwID[0] = 0x7A
	if err := s.RegisterHardwareID("host-0001", hwID); err != nil {
		t.Fatalf("RegisterHardwareID: %v", err)
	}

	if err := deleter.DeleteClient("host-0001"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}

	if _, err := s.GetAIK("host-0001"); !errors.Is(err, ErrAIKNotFound) {
		t.Fatalf("the AIK survived the delete: %v", err)
	}
	if _, err := s.GetHardwareID("host-0001"); err == nil {
		t.Fatal("the hardware-identity binding survived the delete")
	}
	if exists, err := s.HasClient("host-0001"); err != nil || exists {
		t.Fatalf("the client row survived the delete (exists=%v, err=%v)", exists, err)
	}

	// nothing left -> ErrAIKNotFound (API answers 404), as on Postgres
	if err := deleter.DeleteClient("host-0001"); !errors.Is(err, ErrAIKNotFound) {
		t.Fatalf("second delete: %v, want ErrAIKNotFound", err)
	}
}
