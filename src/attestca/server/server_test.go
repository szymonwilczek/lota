// SPDX-License-Identifier: MIT

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/szymonwilczek/lota/attestca/ca"
	"github.com/szymonwilczek/lota/attestca/enroll"
	"github.com/szymonwilczek/lota/attestca/internal/tpmtest"
	"github.com/szymonwilczek/lota/attestca/wire"
)

// serverTLS returns a server TLS certificate for 127.0.0.1 and a cert
// pool a client can use to trust it
func serverTLS(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "lota-attest-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, pool
}

func startServer(t *testing.T, svc *enroll.Service) (addr string, clientPool *x509.CertPool, stop func()) {
	t.Helper()
	tlsCert, pool := serverTLS(t)
	srv, err := New(Config{
		Service:   svc,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ctx, ln)
		close(done)
	}()
	return ln.Addr().String(), pool, func() {
		cancel()
		<-done
	}
}

func newSvc(tb testing.TB) (*enroll.Service, tpmtest.Root) {
	tb.Helper()
	root := tpmtest.NewVendorRoot(tb, "vendor-root")
	caCertPEM, caKeyPEM := tpmtest.LOTACAPEM(tb)
	issuer, err := ca.NewIssuer(ca.IssuerConfig{
		CACertPEM:  caCertPEM,
		CAKeyPEM:   caKeyPEM,
		EKRootPEMs: [][]byte{tpmtest.PEM("CERTIFICATE", root.DER)},
	})
	if err != nil {
		tb.Fatalf("issuer: %v", err)
	}
	svc, err := enroll.NewService(issuer, []byte("pseudonym-key-0123456789abcdef"))
	if err != nil {
		tb.Fatalf("service: %v", err)
	}
	return svc, root
}

// enrollClient runs the agent side of one enrollment over TLS, modelling
// the C agent. When secretOverride is non-nil it is sent in place of the
// activated secret, which exercises the activation-failure path without a
// real TPM
func enrollClient(t *testing.T, addr string, pool *x509.CertPool, ek tpmtest.EK,
	secretOverride []byte,
) (*wire.ChallengeReply, *wire.ResultReply) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	aikTPMT, aikName := tpmtest.AIKTemplate(t)
	beginBody, err := wire.EncodeBegin(&wire.BeginRequest{EKCertDER: ek.CertDER, AIKPublic: aikTPMT})
	if err != nil {
		t.Fatalf("EncodeBegin: %v", err)
	}
	if err := wire.WriteFrame(conn, beginBody); err != nil {
		t.Fatalf("write begin: %v", err)
	}

	challengeBody, err := wire.ReadFrame(conn)
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	challenge, err := wire.DecodeChallenge(challengeBody)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	if challenge.Status != wire.StatusOK {
		return challenge, nil
	}

	secret := secretOverride
	if secret == nil {
		secret = tpmtest.SoftwareActivate(t, ek.Priv, aikName, challenge.CredentialBlob, challenge.EncryptedSecret)
	}

	completeBody, err := wire.EncodeComplete(&wire.CompleteRequest{SessionID: challenge.SessionID, Secret: secret})
	if err != nil {
		t.Fatalf("EncodeComplete: %v", err)
	}
	if err := wire.WriteFrame(conn, completeBody); err != nil {
		t.Fatalf("write complete: %v", err)
	}

	resultBody, err := wire.ReadFrame(conn)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	result, err := wire.DecodeResult(resultBody)
	if err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return challenge, result
}

func TestServerFullEnrollment(t *testing.T) {
	svc, root := newSvc(t)
	addr, pool, stop := startServer(t, svc)
	defer stop()

	ek := tpmtest.NewEKCert(t, root)
	_, result := enrollClient(t, addr, pool, ek, nil)
	if result == nil || result.Status != wire.StatusOK {
		t.Fatalf("enrollment failed: %+v", result)
	}

	aikCert, err := x509.ParseCertificate(result.AIKCertDER)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	if aikCert.Subject.CommonName != result.DeviceID {
		t.Fatalf("cert subject %q != device id %q", aikCert.Subject.CommonName, result.DeviceID)
	}
}

func TestServerRejectsUntrustedEK(t *testing.T) {
	svc, _ := newSvc(t)
	addr, pool, stop := startServer(t, svc)
	defer stop()

	rogue := tpmtest.NewVendorRoot(t, "rogue")
	ek := tpmtest.NewEKCert(t, rogue)
	challenge, result := enrollClient(t, addr, pool, ek, nil)
	if result != nil {
		t.Fatalf("expected rejection at challenge, got result %+v", result)
	}
	if challenge.Status != wire.StatusEKRejected {
		t.Fatalf("status %d, want StatusEKRejected", challenge.Status)
	}
}

func TestServerRejectsWrongActivation(t *testing.T) {
	svc, root := newSvc(t)
	addr, pool, stop := startServer(t, svc)
	defer stop()

	ek := tpmtest.NewEKCert(t, root)
	// a secret the agent could not have recovered from the TPM
	_, result := enrollClient(t, addr, pool, ek, make([]byte, 32))
	if result == nil {
		t.Fatal("expected a result reply")
	}
	if result.Status != wire.StatusActivationFail {
		t.Fatalf("status %d, want StatusActivationFail", result.Status)
	}
}

func newServerForRate(t *testing.T, limit int, win time.Duration) *Server {
	t.Helper()
	svc, _ := newSvc(t)
	tlsCert, _ := serverTLS(t)
	srv, err := New(Config{
		Service:         svc,
		TLSConfig:       &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12},
		BeginRateLimit:  limit,
		BeginRateWindow: win,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

func TestAllowBeginFixedWindow(t *testing.T) {
	srv := newServerForRate(t, 3, time.Minute)
	for i := range 3 {
		if !srv.allowBegin("203.0.113.7:5000") {
			t.Fatalf("call %d from same IP should pass within budget", i)
		}
	}

	// same host, different ephemeral port, must share the counter
	if srv.allowBegin("203.0.113.7:5001") {
		t.Fatal("4th attempt from same IP must be rate-limited")
	}

	// different source IP has its own budget
	if !srv.allowBegin("203.0.113.8:5000") {
		t.Fatal("first attempt from a different IP must pass")
	}
}

func TestAllowBeginWindowResets(t *testing.T) {
	srv := newServerForRate(t, 1, 20*time.Millisecond)
	if !srv.allowBegin("198.51.100.1:1") {
		t.Fatal("first attempt must pass")
	}
	if srv.allowBegin("198.51.100.1:2") {
		t.Fatal("second attempt within the window must be limited")
	}
	time.Sleep(30 * time.Millisecond)
	if !srv.allowBegin("198.51.100.1:3") {
		t.Fatal("attempt after the window elapsed must pass again")
	}
}

func startServerLimit(t *testing.T, svc *enroll.Service, limit int) (string, *x509.CertPool, func()) {
	t.Helper()
	tlsCert, pool := serverTLS(t)
	srv, err := New(Config{
		Service:        svc,
		TLSConfig:      &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12},
		BeginRateLimit: limit,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ctx, ln)
		close(done)
	}()
	return ln.Addr().String(), pool, func() { cancel(); <-done }
}

func TestServerRateLimitsBeginFlood(t *testing.T) {
	svc, root := newSvc(t)
	addr, pool, stop := startServerLimit(t, svc, 1)
	defer stop()

	ek := tpmtest.NewEKCert(t, root)

	// first enrollment from this loopback source consumes the single
	// per-IP Begin slot and succeeds end to end
	_, result := enrollClient(t, addr, pool, ek, nil)
	if result == nil || result.Status != wire.StatusOK {
		t.Fatalf("first enrollment should succeed, got %+v", result)
	}

	// second enrollment from the same source is refused at Begin, before
	// any MakeCredential work, with StatusRateLimited
	ek2 := tpmtest.NewEKCert(t, root)
	challenge, result := enrollClient(t, addr, pool, ek2, nil)
	if result != nil {
		t.Fatalf("expected rejection at challenge, got result %+v", result)
	}
	if challenge.Status != wire.StatusRateLimited {
		t.Fatalf("status %d, want StatusRateLimited", challenge.Status)
	}
}
