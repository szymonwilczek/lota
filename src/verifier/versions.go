// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - Protocol and schema version report

package main

import (
	"fmt"
	"io"

	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
)

// reportWireString renders types.ReportVersion as major.minor.patch.
func reportWireString() string {
	v := types.ReportVersion
	return fmt.Sprintf("%d.%d.%d", (v>>16)&0xffff, (v>>8)&0xff, v&0xff)
}

// writeVersions prints the report wire version, each backend's schema target
// with its fingerprint, and the TLS floor.
func writeVersions(w io.Writer) {
	fmt.Fprintf(w, "attestation report wire:  %s\n", reportWireString())
	fmt.Fprintf(w, "postgres schema target:   %d (%s)\n",
		store.PgTargetSchemaVersion(), store.PgSchemaFingerprint())
	fmt.Fprintf(w, "sqlite schema target:     %d (%s)\n",
		store.SQLiteTargetSchemaVersion(), store.SQLiteSchemaFingerprint())
	// MinVersion of the server.go TLS config, kept in sync by hand
	fmt.Fprintf(w, "minimum TLS:              1.3\n")
}
