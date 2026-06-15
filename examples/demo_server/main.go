// SPDX-License-Identifier: MIT
//
// LOTA demo game server.
//
// Reference integration that issues attestation nonces to game clients
// and verifies anti-cheat heartbeats produced by the LOTA SDK. The
// process is deliberately single-binary, single-listen-address and
// host-local: it is a demo of the framework's wire contract, not a
// production-grade game backend.
//
// Endpoints:
//   POST /nonce      -- mint a session id + 32 random bytes for the
//                       initial trust handshake from the game client.
//   POST /heartbeat  -- decode a LACH wire packet, verify the embedded
//                       LOTA token against the configured AIK public
//                       key, return TRUSTED / UNTRUSTED / REJECT.
//   GET  /state      -- read the most recent verdict the server has
//                       seen for a given game_id; trust_pong polls this
//                       to keep its banner in sync without owning a
//                       heartbeat channel itself.
//
// Transport security is opt-in. With no TLS flags the demo serves plain
// HTTP on 127.0.0.1 so the operator can curl every endpoint without
// bringing in a CA. Pass -tls-cert/-tls-key to serve HTTPS, and add
// -client-ca to require a provisioned anti-cheat producer to present a
// certificate (mutual TLS); see examples/mtls/README.rst.

package main

import (
	"bufio"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// readRuntimeManifest reads a trusted runtime manifest: one ELF path per
// line, with '#' comments and blank lines ignored.
// Returned paths are folded into the expected runtime measurement.
func readRuntimeManifest(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var paths []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		paths = append(paths, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, errors.New("manifest contains no paths")
	}
	return paths, nil
}

const (
	defaultListen   = "127.0.0.1:7443"
	defaultGameID   = "trust-pong"
	defaultLicense  = "lota-demo-CS2-clone"
	shutdownTimeout = 3 * time.Second
)

func main() {
	listen := flag.String("listen", defaultListen,
		"address to listen on (host:port)")
	aikPath := flag.String("aik-pub", "",
		"path to AIK public key (DER or PEM). Required outside test mode.")
	gamesSpec := flag.String("expected-games", defaultGameID+"="+defaultLicense,
		"comma-separated list of game_id=license entries the server accepts")
	maxAgeSec := flag.Uint("max-age", 300,
		"maximum heartbeat age in seconds")
	tlsCert := flag.String("tls-cert", "",
		"PEM server certificate; enables HTTPS (see examples/mtls)")
	tlsKey := flag.String("tls-key", "",
		"PEM server private key; required with -tls-cert")
	clientCA := flag.String("client-ca", "",
		"PEM provisioning CA; when set, require and verify an mTLS "+
			"client certificate from the producer")
	anticheatBin := flag.String("anticheat-binary", "",
		"path to the demo_anticheat producer binary; its SHA-256 is "+
			"mixed into the expected game-binding hash exactly like "+
			"lota_ac_compute_game_binding_hash() does on the client. "+
			"Required for any non-test invocation: leaving it empty "+
			"keeps the server from being able to reproduce the hash "+
			"the heartbeat producer stamps into the LACH header.")
	runtimeManifest := flag.String("anticheat-runtime-manifest", "",
		"path to the trusted runtime manifest: a text file with one "+
			"ELF path per line (the producer binary plus the shared "+
			"libraries it loads), '#' comments and blank lines "+
			"ignored. Capture it with "+
			"'demo_anticheat --print-runtime-objects'. The server "+
			"folds these into the expected runtime measurement. "+
			"When omitted, the runtime measurement falls back to "+
			"--anticheat-binary alone, which only matches a "+
			"statically linked producer.")
	flag.Parse()

	var anticheatDigest [32]byte
	var runtimeMeasure [32]byte
	if *anticheatBin != "" {
		bin, err := os.ReadFile(*anticheatBin)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"demo_server: read --anticheat-binary %s: %v\n",
				*anticheatBin, err)
			os.Exit(2)
		}
		anticheatDigest = sha256.Sum256(bin)

		// Precompute the runtime measurement the producer must report
		// so the server can reject heartbeats whose live code pages
		// diverge from the registered binaries. With a manifest this
		// spans every loaded object; without one it covers just the
		// producer binary (a statically linked image).
		objs := []string{*anticheatBin}
		if *runtimeManifest != "" {
			objs, err = readRuntimeManifest(*runtimeManifest)
			if err != nil {
				fmt.Fprintf(os.Stderr,
					"demo_server: read --anticheat-runtime-manifest %s: %v\n",
					*runtimeManifest, err)
				os.Exit(2)
			}
		}
		runtimeMeasure, err = computeExpectedRuntimeMeasureSet(objs)
		if err != nil {
			fmt.Fprintf(os.Stderr,
				"demo_server: measure runtime manifest: %v\n", err)
			os.Exit(2)
		}
	}

	games, err := parseExpectedGames(*gamesSpec, anticheatDigest,
		runtimeMeasure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "demo_server: bad --expected-games: %v\n", err)
		os.Exit(2)
	}

	aik, err := loadAIK(*aikPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "demo_server: load AIK: %v\n", err)
		os.Exit(2)
	}

	srv, err := newServer(aik, games, time.Duration(*maxAgeSec)*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "demo_server: %v\n", err)
		os.Exit(2)
	}

	http.Handle("/nonce", http.HandlerFunc(srv.handleNonce))
	http.Handle("/heartbeat", http.HandlerFunc(srv.handleHeartbeat))
	http.Handle("/state", http.HandlerFunc(srv.handleState))

	tlsConfig, err := buildTLSConfig(*tlsCert, *tlsKey, *clientCA)
	if err != nil {
		fmt.Fprintf(os.Stderr, "demo_server: %v\n", err)
		os.Exit(2)
	}

	hs := &http.Server{
		Addr:              *listen,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         tlsConfig,
	}

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("demo_server listening on %s (games=%s, transport=%s)",
			*listen, strings.Join(gameIDs(games), ","),
			transportLabel(tlsConfig))
		// ListenAndServeTLS reads the keypair from TLSConfig.Certificates
		// when both path arguments are empty
		var serveErr error
		if tlsConfig != nil {
			serveErr = hs.ListenAndServeTLS("", "")
		} else {
			serveErr = hs.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			log.Fatalf("demo_server: %v", serveErr)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(),
		shutdownTimeout)
	defer cancel()
	if err := hs.Shutdown(shutdownCtx); err != nil {
		log.Printf("demo_server: shutdown: %v", err)
	}
}

// buildTLSConfig turns the transport flags into a *tls.Config, or nil for
// plain HTTP. -tls-cert and -tls-key must be set together; -client-ca adds
// mutual TLS by requiring a producer certificate that verifies against the
// provisioning CA.
func buildTLSConfig(certPath, keyPath, clientCAPath string) (*tls.Config, error) {
	if certPath == "" && keyPath == "" {
		if clientCAPath != "" {
			return nil, errors.New("-client-ca needs -tls-cert/-tls-key")
		}
		return nil, nil
	}
	if certPath == "" || keyPath == "" {
		return nil, errors.New("-tls-cert and -tls-key must be set together")
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if clientCAPath != "" {
		caPEM, err := os.ReadFile(clientCAPath)
		if err != nil {
			return nil, fmt.Errorf("read -client-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no certificate in -client-ca %s", clientCAPath)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

func transportLabel(cfg *tls.Config) string {
	switch {
	case cfg == nil:
		return "http"
	case cfg.ClientAuth == tls.RequireAndVerifyClientCert:
		return "https+mtls"
	default:
		return "https"
	}
}

func gameIDs(games map[string]gameBinding) []string {
	out := make([]string, 0, len(games))
	for id := range games {
		out = append(out, id)
	}
	return out
}

// loadAIK reads a PKIX/SPKI public key from disk. An empty path leaves
// the server without a key; it then rejects every heartbeat with a
// REJECT verdict. The empty path is supported because the unit tests
// build the AIK in memory and inject it through newServer directly.
func loadAIK(path string) (*rsa.PublicKey, error) {
	if path == "" {
		return nil, nil
	}
	der, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return parseAIKBytes(der)
}
