// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Protocol/schema version report
//
// --print-versions writes the protocol and schema versions this binary was
// built against and exits.
// Operators compare the numbers of the old and the new binary before rolling upgrade;
// see the version-compatibility and rolling-upgrade operator docs.

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

// writeVersions prints the versions an operator compares across an upgrade:
// the attestation report wire, the Postgres and SQLite schema targets this
// binary migrates up to, and the TLS floor enforced on every listener.
func writeVersions(w io.Writer) {
	fmt.Fprintf(w, "attestation report wire:  %s\n", reportWireString())
	fmt.Fprintf(w, "postgres schema target:   %d\n", store.PgTargetSchemaVersion())
	fmt.Fprintf(w, "sqlite schema target:     %d\n", store.SQLiteTargetSchemaVersion())
	// every listener pins tls.VersionTLS13 (server.go)
	// kept in sync by hand
	fmt.Fprintf(w, "minimum TLS:              1.3\n")
}
