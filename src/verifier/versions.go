// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Protocol and schema version report
//
// --print-versions writes the versions this binary implements and exits.
//
// Agent and verifier are separate binaries that version independently,
// so the operator needs the report wire version of each to know whether the fleet
// can attest at all: verifier checks it for exact equality and rejects a mismatch.
// Schema targets are what this binary builds a database up to.
// Against the schema_version a live database logs at startup they say whether starting
// this binary runs a migration.
// See the protocol-versions operator doc.

package main

import (
	"fmt"
	"io"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

// reportWireString renders the attestation report wire version as major.minor.patch.
// verifier checks this for exact equality against agent's report,
// so it is the one number that must match the agent fleet.
func reportWireString() string {
	v := types.ReportVersion
	return fmt.Sprintf("%d.%d.%d", (v>>16)&0xffff, (v>>8)&0xff, v&0xff)
}

// writeVersions prints the attestation report wire this binary parses,
// the schema each backend is built to reach, and the TLS floor enforced
// on every listener.
func writeVersions(w io.Writer) {
	fmt.Fprintf(w, "attestation report wire:  %s\n", reportWireString())
	fmt.Fprintf(w, "postgres schema target:   %d\n", store.PgTargetSchemaVersion())
	fmt.Fprintf(w, "sqlite schema target:     %d\n", store.SQLiteTargetSchemaVersion())
	// every listener pins tls.VersionTLS13 (server.go)
	// kept in sync by hand
	fmt.Fprintf(w, "minimum TLS:              1.3\n")
}
