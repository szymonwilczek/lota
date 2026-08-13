// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
//
// Reference release gate for a CI/CD pipeline.
//
// It guards one secret -- signing key, registry credential, deployment token
// -- and hands it over only to a caller that proves, with TPM-signed LOTA token
// answering a challenge this process issued, that it runs on a host in the state
// the gate requires.
//
// The shape is deliberately the smallest thing that is still correct:
// issue a nonce, verify a token against it, apply a policy, release or refuse.
// Production gate differs in what it does after the verdict
// (fetch from a real secret store, mint a short-lived credential, sign an artifact),
// not in the four steps above.

package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8500",
		"host:port to listen on (loopback by default)")
	aikPath := flag.String("aik-pub", "",
		"path to the AIK public key of the host allowed through (PEM or DER)")
	secretPath := flag.String("secret-file", "",
		"file holding the secret to release on success")
	require := flag.String("require", "attested,tpm",
		"comma-separated host state the caller must prove: "+
			"attested, tpm, iommu, bpf, secureboot")
	nonceTTL := flag.Duration("nonce-ttl", 60*time.Second,
		"how long an issued challenge stays spendable")
	maxLife := flag.Duration("max-token-life", 15*time.Minute,
		"refuse a token whose remaining validity exceeds this (0 disables)")
	tlsCert := flag.String("tls-cert", "", "PEM certificate; enables HTTPS")
	tlsKey := flag.String("tls-key", "", "PEM private key for --tls-cert")
	flag.Parse()

	if *aikPath == "" || *secretPath == "" {
		fmt.Fprintln(os.Stderr,
			"both --aik-pub and --secret-file are required")
		os.Exit(2)
	}

	aik, err := loadAIK(*aikPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aik: %v\n", err)
		os.Exit(2)
	}

	secret, err := os.ReadFile(*secretPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "secret: %v\n", err)
		os.Exit(2)
	}
	secret = []byte(strings.TrimRight(string(secret), "\n"))
	if len(secret) == 0 {
		fmt.Fprintln(os.Stderr, "secret: file is empty")
		os.Exit(2)
	}

	required, err := parseFlags(*require)
	if err != nil {
		fmt.Fprintf(os.Stderr, "require: %v\n", err)
		os.Exit(2)
	}

	audit := log.New(os.Stdout, "ci-gate: ", log.LstdFlags|log.LUTC)
	g := &gate{
		aik:      aik,
		secret:   secret,
		required: required,
		maxLife:  *maxLife,
		nonces:   newNonceStore(*nonceTTL),
		audit:    audit,
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           g.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	scheme := "http"
	if *tlsCert != "" || *tlsKey != "" {
		scheme = "https"
	}
	audit.Printf("listening on %s://%s require=[%s] max-token-life=%s",
		scheme, *listen, flagList(required), *maxLife)

	if scheme == "https" {
		err = srv.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		audit.Fatalf("server: %v", err)
	}
}

// loadAIK accepts the key in either of the two forms the tooling around it
// produces: PEM from tpm2_readpublic, DER from the agent's own export.
func loadAIK(path string) (*rsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		der = block.Bytes
	}

	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an RSA public key", path)
	}
	return rsaPub, nil
}
