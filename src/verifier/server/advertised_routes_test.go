// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The startup banner is the operator's inventory of what an instance exposes:
// what a firewall rule, a client or a runbook is written against. A route in it
// the mux does not serve sends the reader after an endpoint that answers 404,
// and a served route missing from it hides an exposed surface.
// Both directions are asserted against the mux the server builds, by asking
// the mux which pattern it matches rather than what the handler answers
// -- a handler may legitimately answer 404 for a client that does not exist.

// concreteRequestPath turns an advertised endpoint into a path a request can
// carry: the identifier placeholder gets a value.
func concreteRequestPath(path string) string {
	return strings.ReplaceAll(path, "{id}", "test-client")
}

// matchedPattern is the route the mux would dispatch this endpoint to,
// or "" when nothing is registered for it.
func matchedPattern(t *testing.T, mux *http.ServeMux, endpoint string) string {
	t.Helper()

	method, path, found := strings.Cut(endpoint, " ")
	if !found {
		t.Fatalf("endpoint %q is not \"METHOD /path\"", endpoint)
	}

	req := httptest.NewRequest(method, concreteRequestPath(path),
		strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")

	_, pattern := mux.Handler(req)
	return pattern
}

func TestEveryAdvertisedEndpointIsServed(t *testing.T) {
	mux := http.NewServeMux()
	h := NewAPIHandler(mux, nil, nil, nil, nil, nil, nil, "", "")

	for _, endpoint := range h.AdvertisedRoutes() {
		if matchedPattern(t, mux, endpoint) == "" {
			t.Errorf("advertised endpoint %q is served by nothing",
				endpoint)
		}
	}
}

func TestEveryServedRouteIsAdvertised(t *testing.T) {
	mux := http.NewServeMux()
	h := NewAPIHandler(mux, nil, nil, nil, nil, nil, nil, "", "")

	// A route that dispatches several endpoints under one pattern is advertised
	// by those endpoints, so the pattern is covered when any advertised endpoint
	// routes back to it.
	covered := make(map[string]bool)
	for _, endpoint := range h.AdvertisedRoutes() {
		covered[matchedPattern(t, mux, endpoint)] = true
	}

	for _, pattern := range h.RegisteredRoutes() {
		if !covered[pattern] {
			t.Errorf("route %q is served and advertised by no endpoint",
				pattern)
		}
	}
}
