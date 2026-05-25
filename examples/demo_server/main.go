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
// TLS is deliberately out of scope: the demo runs on 127.0.0.1 so the
// operator can curl every endpoint without bringing in a CA.

package main

import (
	"context"
	"crypto/rsa"
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
	flag.Parse()

	games, err := parseExpectedGames(*gamesSpec)
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

	hs := &http.Server{
		Addr:              *listen,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("demo_server listening on %s (games=%s)", *listen,
			strings.Join(gameIDs(games), ","))
		if err := hs.ListenAndServe(); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("demo_server: %v", err)
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
