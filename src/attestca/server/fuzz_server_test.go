// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package server

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// FuzzServerHandle drives the full enrollment connection handler with
// arbitrary client bytes over an in-memory pipe. handle reads framed
// begin/complete requests off the wire and runs the ceremony; whatever the
// peer sends, it must never panic.
func FuzzServerHandle(f *testing.F) {
	svc, _ := newSvc(f)
	srv, err := New(Config{
		Service:      svc,
		TLSConfig:    &tls.Config{},
		ReadTimeout:  20 * time.Millisecond,
		WriteTimeout: 20 * time.Millisecond,
	})
	if err != nil {
		f.Fatalf("New: %v", err)
	}

	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		client, server := net.Pipe()
		go func() {
			_ = client.SetDeadline(time.Now().Add(100 * time.Millisecond))
			_, _ = client.Write(data)
			_, _ = io.Copy(io.Discard, client)
			_ = client.Close()
		}()
		srv.handle(server) // closes the server side via defer
	})
}
