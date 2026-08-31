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

// The defect this pair exists for: a tenant-scoped administrator could impose
// a ban through the body's `tenant` and could not lift it, because the lift
// read the tenant off the URL and resolved `default`.
func TestScopedAdminCanLiftTheBanItImposed(t *testing.T) {
	set, err := LoadAPIKeysFile(writeKeysFile(t, fmt.Sprintf(`keys:
  - key_sha256: %s
    role: admin
    tenants: ["acme"]
`, keyHashHex("body-admin"))))
	if err != nil {
		t.Fatalf("LoadAPIKeysFile: %v", err)
	}
	mux := newScopedKeyAPI(t, set)
	hwid := strings.Repeat("1a", 32)

	code, _ := postJSON(t, mux, "POST", "/api/v1/bans",
		`{"hardware_id":"`+hwid+`","tenant":"acme","reason":"cheating","actor":"acmeops"}`)
	if code != http.StatusCreated {
		t.Fatalf("ban in the key's own tenant: %d, want 201", code)
	}

	code, body := postJSON(t, mux, "DELETE", "/api/v1/bans/"+hwid,
		`{"tenant":"acme","reason":"appeal upheld","actor":"acmeops"}`)
	if code != http.StatusOK {
		t.Fatalf("unban in the key's own tenant: %d (%v), want 200", code, body)
	}
	if body["tenant"] != "acme" {
		t.Fatalf("unban tenant = %v, want acme", body["tenant"])
	}
}

// The scope check still holds: naming a foreign tenant in the body is refused.
func TestUnbanRefusesAForeignTenant(t *testing.T) {
	set, err := LoadAPIKeysFile(writeKeysFile(t, fmt.Sprintf(`keys:
  - key_sha256: %s
    role: admin
    tenants: ["acme"]
`, keyHashHex("body-admin"))))
	if err != nil {
		t.Fatalf("LoadAPIKeysFile: %v", err)
	}
	mux := newScopedKeyAPI(t, set)

	code, _ := postJSON(t, mux, "DELETE", "/api/v1/bans/"+strings.Repeat("2b", 32),
		`{"tenant":"beta","reason":"x","actor":"acmeops"}`)
	if code != http.StatusForbidden {
		t.Fatalf("unban into a foreign tenant: %d, want 403", code)
	}
}

// The tenant moved out of the query string, so a caller still sending it there
// hears about it instead of lifting a ban in the default tenant.
func TestUnbanRefusesTheTenantAsAQueryParameter(t *testing.T) {
	mux := bodyTestAPI(t)

	code, body := postJSON(t, mux, "DELETE",
		"/api/v1/bans/"+strings.Repeat("3c", 32)+"?tenant=acme",
		`{"reason":"x","actor":"ops"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("unban with ?tenant=: %d, want 400", code)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "body field") {
		t.Fatalf("refusal %q must say where the tenant belongs", msg)
	}
}
