// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Verifier - request body strictness tests

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// bodyTestAPI builds an admin-keyed handler over the scoped-key fixture
func bodyTestAPI(t *testing.T) *http.ServeMux {
	t.Helper()

	set, err := LoadAPIKeysFile(writeKeysFile(t, fmt.Sprintf(`keys:
  - key_sha256: %s
    role: admin
    tenants: ["*"]
`, keyHashHex("body-admin"))))
	if err != nil {
		t.Fatalf("LoadAPIKeysFile: %v", err)
	}
	return newScopedKeyAPI(t, set)
}

func postJSON(t *testing.T, mux *http.ServeMux, method, target, body string) (int, map[string]any) {
	t.Helper()

	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer body-admin")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	var out map[string]any
	if rr.Body.Len() > 0 {
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
	}
	return rr.Code, out
}

// A field the handler does not read is a request that did not do what its author
// wrote. Dropping it silently is how a caller names one tenant and has the action
// carried out in another.
func TestRequestBodyRefusesAFieldTheHandlerDoesNotRead(t *testing.T) {
	mux := bodyTestAPI(t)
	hwid := strings.Repeat("ab", 32)

	code, body := postJSON(t, mux, "POST", "/api/v1/bans",
		`{"hardware_id":"`+hwid+`","reason":"admin","actor":"ops","scope":"acme"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("ban with an unknown field: %d, want 400", code)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "scope") {
		t.Fatalf("refusal %q must name the field it did not read", msg)
	}
}

// The fields the endpoint does read still work, so the strictness costs a caller
// nothing that follows the documented shape.
func TestRequestBodyAcceptsTheDocumentedFields(t *testing.T) {
	mux := bodyTestAPI(t)
	hwid := strings.Repeat("cd", 32)

	code, _ := postJSON(t, mux, "POST", "/api/v1/bans",
		`{"hardware_id":"`+hwid+`","tenant":"acme","reason":"cheating","actor":"ops","note":"n"}`)
	if code != http.StatusCreated {
		t.Fatalf("documented ban body: %d, want 201", code)
	}
}
