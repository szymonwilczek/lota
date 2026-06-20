// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
package server

import (
	"encoding/hex"
	"net/http"
	"testing"
)

func TestNewChallengeID_UniqueAndHex(t *testing.T) {
	id1, err := newChallengeID()
	if err != nil {
		t.Fatalf("newChallengeID 1: %v", err)
	}
	id2, err := newChallengeID()
	if err != nil {
		t.Fatalf("newChallengeID 2: %v", err)
	}
	if id1 == id2 {
		t.Fatalf("expected different challenge IDs, got same: %q", id1)
	}
	if len(id1) != 32 {
		t.Fatalf("expected 32 hex chars, got %d (%q)", len(id1), id1)
	}
	if _, err := hex.DecodeString(id1); err != nil {
		t.Fatalf("id1 is not hex: %q: %v", id1, err)
	}
}

// monitoring HTTP server must set every slow-client timeout, including
// ReadHeaderTimeout, which bounds the header-read phase on its own so a
// slow-header client cannot hold a connection for the full ReadTimeout
func TestNewMonitoringHTTPServer_Timeouts(t *testing.T) {
	srv := newMonitoringHTTPServer("127.0.0.1:0", http.NewServeMux())

	if srv.ReadTimeout <= 0 {
		t.Errorf("ReadTimeout not set: %v", srv.ReadTimeout)
	}
	if srv.WriteTimeout <= 0 {
		t.Errorf("WriteTimeout not set: %v", srv.WriteTimeout)
	}
	if srv.IdleTimeout <= 0 {
		t.Errorf("IdleTimeout not set: %v", srv.IdleTimeout)
	}
	if srv.ReadHeaderTimeout <= 0 {
		t.Errorf("ReadHeaderTimeout not set: %v", srv.ReadHeaderTimeout)
	}
	if srv.ReadHeaderTimeout > srv.ReadTimeout {
		t.Errorf("ReadHeaderTimeout %v exceeds ReadTimeout %v",
			srv.ReadHeaderTimeout, srv.ReadTimeout)
	}
}
