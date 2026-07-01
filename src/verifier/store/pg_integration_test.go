// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
//go:build pg_integration

// Integration tests for the Postgres store implementations.
//
// They require a live Postgres reachable at LOTA_TEST_PG_DSN and are gated
// behind the pg_integration build tag so the normal `go test ./...` run does
// not need a database.
//
// CI runs them against a postgres service container; locally:
//
//	podman run -d -e POSTGRES_PASSWORD=lota -e POSTGRES_USER=lota \
//	  -e POSTGRES_DB=lota -p 55432:5432 docker.io/library/postgres:16-alpine
//	LOTA_TEST_PG_DSN="postgres://lota:lota@127.0.0.1:55432/lota?sslmode=disable" \
//	  go test -tags pg_integration -p 1 ./store/ ./verify/ -v
//
// Use -p 1 when running both packages: they share one database, so parallel
// package execution would let one package's TRUNCATE stomp the other's rows.

package store

import (
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"errors"
	"os"
	"testing"
)

func pgTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("LOTA_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("LOTA_TEST_PG_DSN not set; skipping Postgres integration test")
	}
	db, err := OpenPostgresDB(dsn)
	if err != nil {
		t.Fatalf("OpenPostgresDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(
		"TRUNCATE clients, baselines, used_nonces, revocations, hardware_bans, audit_log, attestation_log"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return db
}

func TestPostgresMigrationsIdempotent(t *testing.T) {
	db := pgTestDB(t)
	// second open over the same database must be a no-op
	// (advisory lock + schema_version check),
	// not a duplicate-DDL failure
	dsn := os.Getenv("LOTA_TEST_PG_DSN")
	db2, err := OpenPostgresDB(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	v, err := SchemaVersion(db)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if v != len(pgMigrations) {
		t.Fatalf("schema version = %d, want %d", v, len(pgMigrations))
	}
}

func TestPostgresAIKStore(t *testing.T) {
	db := pgTestDB(t)
	s := NewPostgresAIKStore(db)

	k1, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := s.RegisterAIK("c1", &k1.PublicKey); err != nil {
		t.Fatalf("RegisterAIK: %v", err)
	}
	if err := s.RegisterAIK("c1", &k1.PublicKey); err != nil {
		t.Fatalf("RegisterAIK idempotent: %v", err)
	}
	// same key, different client -> global uniqueness rejection
	if err := s.RegisterAIK("c2", &k1.PublicKey); err == nil {
		t.Fatal("expected ErrAIKAlreadyRegistered for duplicate key")
	}

	got, err := s.GetAIK("c1")
	if err != nil || got.N.Cmp(k1.PublicKey.N) != 0 {
		t.Fatalf("GetAIK: %v", err)
	}

	var hw [32]byte
	hw[0] = 0xAB
	if err := s.RegisterHardwareID("c1", hw); err != nil {
		t.Fatalf("RegisterHardwareID: %v", err)
	}
	var hw2 [32]byte
	hw2[0] = 0xCD
	if err := s.RegisterHardwareID("c1", hw2); err != ErrHardwareIDMismatch {
		t.Fatalf("hardware mismatch: got %v want ErrHardwareIDMismatch", err)
	}

	k2, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := s.RotateAIK("c1", &k2.PublicKey); err != nil {
		t.Fatalf("RotateAIK: %v", err)
	}
	got2, _ := s.GetAIK("c1")
	if got2.N.Cmp(k2.PublicKey.N) != 0 {
		t.Fatal("RotateAIK did not replace the key")
	}
	if gh, _ := s.GetHardwareID("c1"); gh != hw {
		t.Fatal("RotateAIK lost the hardware-ID binding")
	}
	if n := s.CountClients(); n != 1 {
		t.Fatalf("CountClients = %d, want 1", n)
	}
	if ex, _ := s.ExistingClients([]string{"c1", "cX"}); len(ex) != 1 {
		t.Fatalf("ExistingClients = %v", ex)
	}

	// cert-carrying registration delegates to the same uniqueness contract
	k3, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := s.RegisterAIKWithCert("c3", &k3.PublicKey, []byte{0x30}, []byte{0x30}); err != nil {
		t.Fatalf("RegisterAIKWithCert: %v", err)
	}

	if cl := s.ListClients(); len(cl) != 2 || cl[0] != "c1" || cl[1] != "c3" {
		t.Fatalf("ListClients = %v", cl)
	}
	if cl := s.ListClientsPage(1, 1); len(cl) != 1 || cl[0] != "c3" {
		t.Fatalf("ListClientsPage = %v", cl)
	}
	if ok, err := s.HasClient("c1"); err != nil || !ok {
		t.Fatalf("HasClient c1: %v %v", ok, err)
	}
	if ok, err := s.HasClient("cX"); err != nil || ok {
		t.Fatalf("HasClient cX: %v %v", ok, err)
	}
	if at, err := s.GetRegisteredAt("c1"); err != nil || at.IsZero() {
		t.Fatalf("GetRegisteredAt: %v %v", at, err)
	}
	if _, err := s.GetRegisteredAt("cX"); err == nil {
		t.Fatal("GetRegisteredAt on unknown client should fail")
	}

	// operator-forced re-enrollment:
	// delete frees the row and the AIK-uniqueness slot,
	// unknown client maps to ErrAIKNotFound
	if err := s.DeleteClient("c3"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if _, err := s.GetAIK("c3"); !errors.Is(err, ErrAIKNotFound) {
		t.Fatalf("GetAIK after delete: %v, want ErrAIKNotFound", err)
	}
	if err := s.DeleteClient("c3"); !errors.Is(err, ErrAIKNotFound) {
		t.Fatalf("DeleteClient on unknown client: %v, want ErrAIKNotFound", err)
	}
	if err := s.RegisterAIK("c4", &k3.PublicKey); err != nil {
		t.Fatalf("re-registering the freed AIK failed: %v", err)
	}
}

func TestPostgresRevocationBanAudit(t *testing.T) {
	db := pgTestDB(t)
	audit := NewPostgresAuditLog(db)
	rev := NewPostgresRevocationStore(db, audit)

	if err := rev.Revoke("c1", RevocationReason("compromised"), "op", "n1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := rev.Revoke("c1", RevocationReason("compromised"), "op", "n1"); err != ErrAlreadyRevoked {
		t.Fatalf("duplicate Revoke: got %v want ErrAlreadyRevoked", err)
	}
	if e, ok := rev.IsRevoked("c1"); !ok || e.RevokedBy != "op" {
		t.Fatal("IsRevoked")
	}
	if lr := rev.ListRevocations(); len(lr) != 1 || lr[0].ClientID != "c1" {
		t.Fatalf("ListRevocations = %+v", lr)
	}
	if err := rev.Unrevoke("c1"); err != nil {
		t.Fatalf("Unrevoke: %v", err)
	}
	if err := rev.Unrevoke("c1"); err != ErrNotRevoked {
		t.Fatalf("double Unrevoke: got %v want ErrNotRevoked", err)
	}

	ban := NewPostgresBanStore(db, audit)
	var hw [32]byte
	hw[0] = 0x09
	if err := ban.BanHardware(hw, RevocationReason("cheat"), "op", "b1"); err != nil {
		t.Fatalf("BanHardware: %v", err)
	}
	if err := ban.BanHardware(hw, RevocationReason("cheat"), "op", "b1"); err != ErrAlreadyBanned {
		t.Fatalf("duplicate ban: got %v want ErrAlreadyBanned", err)
	}
	if e, ok := ban.IsBanned(hw); !ok || e.HardwareID != hw {
		t.Fatal("IsBanned")
	}
	if ban.CountBans() != 1 {
		t.Fatalf("CountBans = %d, want 1", ban.CountBans())
	}
	if lb, err := ban.ListBansAfter(10, ""); err != nil || len(lb) != 1 {
		t.Fatalf("ListBansAfter: %v len=%d", err, len(lb))
	}
	if lb := ban.ListBans(); len(lb) != 1 || lb[0].HardwareID != hw {
		t.Fatalf("ListBans = %+v", lb)
	}
	if lb := ban.ListBansPage(1, 0); len(lb) != 1 {
		t.Fatalf("ListBansPage = %+v", lb)
	}
	if err := ban.UnbanHardware(hw); err != nil {
		t.Fatalf("UnbanHardware: %v", err)
	}
	if err := ban.UnbanHardware(hw); err != ErrNotBanned {
		t.Fatalf("double unban: got %v want ErrNotBanned", err)
	}

	// revoke + unrevoke + ban + unban = four audit entries
	if n := len(audit.Query(100)); n != 4 {
		t.Fatalf("audit entries = %d, want 4", n)
	}
}

func TestPostgresAttestationLog(t *testing.T) {
	db := pgTestDB(t)
	al := NewPostgresAttestationLog(db)
	if err := al.Record(AttestationRecord{ClientID: "c1", Result: "VERIFY_OK", DurationMs: 1.5}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	rs := al.QueryAttestations(10)
	if len(rs) != 1 || rs[0].Result != "VERIFY_OK" {
		t.Fatalf("QueryAttestations = %+v", rs)
	}
}
