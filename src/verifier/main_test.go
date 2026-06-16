// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
package main

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateTestCertIncludesLoopbackSAN(t *testing.T) {
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("Chdir(temp): %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWD); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})

	if err := generateTestCert(); err != nil {
		t.Fatalf("generateTestCert: %v", err)
	}

	pemBytes, err := os.ReadFile(filepath.Join(tmp, "lota-verifier.crt"))
	if err != nil {
		t.Fatalf("ReadFile(cert): %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("certificate PEM did not contain a block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	if !cert.IsCA {
		t.Fatal("generated verifier certificate must be usable as a test trust anchor")
	}
	if err := cert.VerifyHostname("localhost"); err != nil {
		t.Fatalf("localhost SAN missing: %v", err)
	}
	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("127.0.0.1 IP SAN missing: %v", err)
	}
	if len(cert.IPAddresses) == 0 || !cert.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("expected first IP SAN to be 127.0.0.1, got %#v", cert.IPAddresses)
	}
}
