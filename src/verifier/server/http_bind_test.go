// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
package server

import (
	"crypto/tls"
	"strings"
	"testing"

	"github.com/szymonwilczek/lota/verifier/logging"
)

func TestIsLoopbackAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"[::1]:8080", true},
		{"0.0.0.0:8080", false},
		{"[::]:8080", false},
		{"192.168.1.10:8080", false},
		{":8080", false},   // empty host = wildcard
		{"garbage", false}, // unparseable
	}
	for _, c := range cases {
		if got := isLoopbackAddr(c.addr); got != c.want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

// builds a minimal Server suitable for exercising startHTTP's bind guards
// without standing up the attestation protocol listener
func newHTTPGuardServer(httpAddr string, tlsCfg *tls.Config, adminKey, readerKey string) *Server {
	return &Server{
		httpAddr:     httpAddr,
		tlsConfig:    tlsCfg,
		adminAPIKey:  adminKey,
		readerAPIKey: readerKey,
		log:          logging.Nop(),
		shutdownCh:   make(chan struct{}),
	}
}

func TestStartHTTP_NonLoopbackRequiresTLS(t *testing.T) {
	s := newHTTPGuardServer("0.0.0.0:0", nil, "admin", "reader")
	err := s.startHTTP()
	if err == nil {
		s.httpServer.Close()
		t.Fatal("expected non-loopback bind without TLS to be refused")
	}
	if !strings.Contains(err.Error(), "requires TLS") {
		t.Fatalf("expected TLS error, got: %v", err)
	}
}

func TestStartHTTP_NonLoopbackRequiresAuth(t *testing.T) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	s := newHTTPGuardServer("0.0.0.0:0", tlsCfg, "", "")
	err := s.startHTTP()
	if err == nil {
		s.httpServer.Close()
		t.Fatal("expected non-loopback bind without auth tier to be refused")
	}
	if !strings.Contains(err.Error(), "requires authentication") {
		t.Fatalf("expected authentication error, got: %v", err)
	}
}

func TestStartHTTP_NonLoopbackAdminKeySuffices(t *testing.T) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	s := newHTTPGuardServer("0.0.0.0:0", tlsCfg, "admin", "")
	if err := s.startHTTP(); err != nil {
		t.Fatalf("admin key alone should satisfy the non-loopback auth requirement: %v", err)
	}
	s.httpServer.Close()
}

func TestStartHTTP_NonLoopbackReaderKeySuffices(t *testing.T) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	s := newHTTPGuardServer("0.0.0.0:0", tlsCfg, "", "reader")
	if err := s.startHTTP(); err != nil {
		t.Fatalf("reader key should satisfy the non-loopback auth requirement: %v", err)
	}
	s.httpServer.Close()
}

func TestStartHTTP_LoopbackNoAuthAllowed(t *testing.T) {
	s := newHTTPGuardServer("127.0.0.1:0", nil, "", "")
	if err := s.startHTTP(); err != nil {
		t.Fatalf("loopback bind without TLS or auth should be allowed: %v", err)
	}
	s.httpServer.Close()
}
