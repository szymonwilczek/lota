// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	verifysdk "github.com/szymonwilczek/lota/sdk/server"
)

// The tests mint tokens with a software RSA key rather than a TPM.
// Signature algorithm and the quote binding are the same either way,
// so every gate decision below is exercised for real;
// what a TPM adds is that the key cannot be copied,
// which is not a property a unit test can check.
type tokenOpts struct {
	flags      uint32
	validFor   time.Duration
	nonce      [32]byte
	signWith   *rsa.PrivateKey
	corruptSig bool
}

func newGate(t *testing.T, key *rsa.PrivateKey, required uint32,
	maxLife time.Duration,
) *gate {
	t.Helper()
	return &gate{
		aik:      &key.PublicKey,
		secret:   []byte("registry-credential"),
		required: required,
		maxLife:  maxLife,
		nonces:   newNonceStore(time.Minute),
		audit:    log.New(io.Discard, "", 0),
	}
}

func mintToken(t *testing.T, opts tokenOpts) []byte {
	t.Helper()

	validUntil := uint64(time.Now().Add(opts.validFor).Unix())
	pcrMask := uint32(0x4083)
	policyDigest := [32]byte{0xA1, 0xB2, 0xC3}
	runtimeDigest := emptyRuntimeProtectDigest()

	pcrDigest := make([]byte, 32)
	for i := range pcrDigest {
		pcrDigest[i] = byte(i)
	}

	quoteNonce := verifysdk.ComputeTokenQuoteNonce(validUntil, opts.flags,
		pcrMask, opts.nonce, policyDigest, runtimeDigest, 0)
	attest := fakeTPMSAttest(quoteNonce[:], pcrMask, pcrDigest)

	hash := sha256.Sum256(attest)
	sig, err := rsa.SignPKCS1v15(rand.Reader, opts.signWith, crypto.SHA256,
		hash[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if opts.corruptSig {
		sig[0] ^= 0xFF
	}

	token, err := verifysdk.SerializeToken(validUntil, opts.flags, opts.nonce,
		0x0014, 0x000B, pcrMask, policyDigest, runtimeDigest, nil, attest, sig)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return token
}

// emptyRuntimeProtectDigest is the canonical digest of an empty protected PID set,
// which is what an agent with nothing under runtime protection puts in the token.
// The v1 form of this helper is internal to the SDK,
// so a caller minting synthetic tokens reproduces it;
// caller verifying them never needs to.
func emptyRuntimeProtectDigest() [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("lota-runtime-protect-pids:v1\x00"))
	var le [4]byte
	binary.LittleEndian.PutUint32(le[:], 0)
	_, _ = h.Write(le[:])

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// fakeTPMSAttest builds the TPMS_ATTEST layout the verifier parses,
// with the fields it reads in the places it reads them.
func fakeTPMSAttest(extraData []byte, pcrMask uint32, pcrDigest []byte) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint32(b, 0xff544347)
	b = binary.BigEndian.AppendUint16(b, 0x8018)
	b = binary.BigEndian.AppendUint16(b, 4)
	b = append(b, 0x00, 0x0B, 0xAA, 0xBB)
	b = binary.BigEndian.AppendUint16(b, uint16(len(extraData)))
	b = append(b, extraData...)
	b = append(b, make([]byte, 17)...)
	b = append(b, make([]byte, 8)...)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = binary.BigEndian.AppendUint16(b, 0x000B)
	b = append(b, 3)
	b = append(b, byte(pcrMask), byte(pcrMask>>8), byte(pcrMask>>16))
	b = binary.BigEndian.AppendUint16(b, uint16(len(pcrDigest)))
	b = append(b, pcrDigest...)
	return b
}

// requestNonce drives the real handler,
// so the tests spend the same challenges a client would.
func requestNonce(t *testing.T, g *gate) [32]byte {
	t.Helper()

	w := httptest.NewRecorder()
	g.routes().ServeHTTP(w,
		httptest.NewRequest(http.MethodPost, "/nonce", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("nonce: status %d", w.Code)
	}

	var resp nonceResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("nonce decode: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(resp.Nonce)
	if err != nil || len(raw) != 32 {
		t.Fatalf("nonce is not 32 bytes: %v", err)
	}

	var nonce [32]byte
	copy(nonce[:], raw)
	return nonce
}

func postRelease(g *gate, nonce [32]byte, token []byte) (int, releaseResponse) {
	body, _ := json.Marshal(releaseRequest{
		Nonce: base64.StdEncoding.EncodeToString(nonce[:]),
		Token: base64.StdEncoding.EncodeToString(token),
	})

	w := httptest.NewRecorder()
	g.routes().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/release",
		bytes.NewReader(body)))

	var resp releaseResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

func TestRelease_GrantsOnAttestedHost(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	g := newGate(t, key, flagAttested|flagTPMOK, 15*time.Minute)

	nonce := requestNonce(t, g)
	token := mintToken(t, tokenOpts{
		flags:    flagAttested | flagTPMOK | flagSecureBoot,
		validFor: 5 * time.Minute,
		nonce:    nonce,
		signWith: key,
	})

	code, resp := postRelease(g, nonce, token)
	if code != http.StatusOK {
		t.Fatalf("status %d, reason %q", code, resp.Reason)
	}

	secret, err := base64.StdEncoding.DecodeString(resp.Secret)
	if err != nil {
		t.Fatalf("secret decode: %v", err)
	}
	if string(secret) != "registry-credential" {
		t.Fatalf("released %q", secret)
	}
}

func TestRelease_RefusesTokenFromAnotherTPM(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	g := newGate(t, key, flagAttested, 15*time.Minute)

	nonce := requestNonce(t, g)
	token := mintToken(t, tokenOpts{
		flags:    flagAttested | flagTPMOK,
		validFor: 5 * time.Minute,
		nonce:    nonce,
		signWith: other,
	})

	code, resp := postRelease(g, nonce, token)
	if code != http.StatusForbidden {
		t.Fatalf("status %d, expected refusal", code)
	}
	if resp.Secret != "" {
		t.Fatal("secret released to a token signed by another key")
	}
	if !strings.Contains(resp.Reason, "verification failed") {
		t.Fatalf("reason %q", resp.Reason)
	}
}

func TestRelease_RefusesTamperedSignature(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	g := newGate(t, key, flagAttested, 15*time.Minute)

	nonce := requestNonce(t, g)
	token := mintToken(t, tokenOpts{
		flags:      flagAttested,
		validFor:   5 * time.Minute,
		nonce:      nonce,
		signWith:   key,
		corruptSig: true,
	})

	code, resp := postRelease(g, nonce, token)
	if code != http.StatusForbidden || resp.Secret != "" {
		t.Fatalf("status %d secret=%q", code, resp.Secret)
	}
}

// token is bound to the challenge it answered,
// so one captured from another pipeline run is worthless here.
func TestRelease_RefusesTokenBoundToAnotherChallenge(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	g := newGate(t, key, flagAttested, 15*time.Minute)

	captured := requestNonce(t, g)
	token := mintToken(t, tokenOpts{
		flags:    flagAttested,
		validFor: 5 * time.Minute,
		nonce:    captured,
		signWith: key,
	})

	current := requestNonce(t, g)
	code, resp := postRelease(g, current, token)
	if code != http.StatusForbidden || resp.Secret != "" {
		t.Fatalf("status %d secret=%q", code, resp.Secret)
	}
}

// nonce is spent by the attempt, not by the verdict:
// caller that replays a token against the challenge it was minted for is refused
// the second time even though the first attempt succeeded.
func TestRelease_NonceIsSingleUse(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	g := newGate(t, key, flagAttested, 15*time.Minute)

	nonce := requestNonce(t, g)
	token := mintToken(t, tokenOpts{
		flags:    flagAttested,
		validFor: 5 * time.Minute,
		nonce:    nonce,
		signWith: key,
	})

	if code, resp := postRelease(g, nonce, token); code != http.StatusOK {
		t.Fatalf("first attempt: status %d reason %q", code, resp.Reason)
	}

	code, resp := postRelease(g, nonce, token)
	if code != http.StatusForbidden || resp.Secret != "" {
		t.Fatalf("replay accepted: status %d", code)
	}
	if !strings.Contains(resp.Reason, "not issued") {
		t.Fatalf("reason %q", resp.Reason)
	}
	if g.nonces.outstanding() != 0 {
		t.Fatalf("%d nonces outstanding", g.nonces.outstanding())
	}
}

// failed attempt must also spend its nonce,
// or a captured token could be ground against the gate until some other
// condition changes.
func TestRelease_FailedAttemptStillSpendsTheNonce(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	g := newGate(t, key, flagAttested, 15*time.Minute)

	nonce := requestNonce(t, g)
	bad := mintToken(t, tokenOpts{
		flags:    flagAttested,
		validFor: 5 * time.Minute,
		nonce:    nonce,
		signWith: other,
	})
	if code, _ := postRelease(g, nonce, bad); code != http.StatusForbidden {
		t.Fatalf("first attempt should fail, got %d", code)
	}

	good := mintToken(t, tokenOpts{
		flags:    flagAttested,
		validFor: 5 * time.Minute,
		nonce:    nonce,
		signWith: key,
	})
	code, resp := postRelease(g, nonce, good)
	if code != http.StatusForbidden || resp.Secret != "" {
		t.Fatalf("spent nonce reused: status %d", code)
	}
}

func TestRelease_RefusesHostMissingRequiredState(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	g := newGate(t, key, flagAttested|flagSecureBoot, 15*time.Minute)

	nonce := requestNonce(t, g)
	token := mintToken(t, tokenOpts{
		flags:    flagAttested | flagTPMOK,
		validFor: 5 * time.Minute,
		nonce:    nonce,
		signWith: key,
	})

	code, resp := postRelease(g, nonce, token)
	if code != http.StatusForbidden || resp.Secret != "" {
		t.Fatalf("status %d secret=%q", code, resp.Secret)
	}
	if !strings.Contains(resp.Reason, "secureboot") {
		t.Fatalf("reason %q should name the missing state", resp.Reason)
	}
}

func TestRelease_RefusesExpiredToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	g := newGate(t, key, flagAttested, 15*time.Minute)

	nonce := requestNonce(t, g)
	token := mintToken(t, tokenOpts{
		flags:    flagAttested,
		validFor: -time.Minute,
		nonce:    nonce,
		signWith: key,
	})

	code, resp := postRelease(g, nonce, token)
	if code != http.StatusForbidden || resp.Secret != "" {
		t.Fatalf("expired token accepted: status %d", code)
	}
}

// gate's own freshness policy, since the SDK has none:
// token that outlives the window is refused even though it verifies.
func TestRelease_RefusesTokenOutlivingTheWindow(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	g := newGate(t, key, flagAttested, time.Minute)

	nonce := requestNonce(t, g)
	token := mintToken(t, tokenOpts{
		flags:    flagAttested,
		validFor: 5 * time.Minute,
		nonce:    nonce,
		signWith: key,
	})

	code, resp := postRelease(g, nonce, token)
	if code != http.StatusForbidden || resp.Secret != "" {
		t.Fatalf("status %d secret=%q", code, resp.Secret)
	}
	if !strings.Contains(resp.Reason, "outlives") {
		t.Fatalf("reason %q", resp.Reason)
	}
}

func TestRelease_RefusesExpiredNonce(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	g := newGate(t, key, flagAttested, 15*time.Minute)
	g.nonces.ttl = time.Millisecond

	nonce := requestNonce(t, g)
	token := mintToken(t, tokenOpts{
		flags:    flagAttested,
		validFor: 5 * time.Minute,
		nonce:    nonce,
		signWith: key,
	})
	time.Sleep(5 * time.Millisecond)

	code, resp := postRelease(g, nonce, token)
	if code != http.StatusForbidden || resp.Secret != "" {
		t.Fatalf("status %d secret=%q", code, resp.Secret)
	}
	if !strings.Contains(resp.Reason, "expired") {
		t.Fatalf("reason %q", resp.Reason)
	}
}

func TestRelease_RefusesMalformedInput(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	g := newGate(t, key, flagAttested, 15*time.Minute)

	cases := map[string]string{
		"not json":      "{",
		"short nonce":   `{"nonce":"AAAA","token":"AAAA"}`,
		"empty token":   `{"nonce":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `","token":""}`,
		"nonce not b64": `{"nonce":"!!!!","token":"AAAA"}`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			g.routes().ServeHTTP(w, httptest.NewRequest(http.MethodPost,
				"/release", strings.NewReader(body)))
			if w.Code != http.StatusForbidden {
				t.Fatalf("status %d", w.Code)
			}
			if strings.Contains(w.Body.String(), "secret") {
				t.Fatalf("body leaked a secret field: %s", w.Body.String())
			}
		})
	}
}

func TestParseFlags(t *testing.T) {
	mask, err := parseFlags("attested, secureboot")
	if err != nil {
		t.Fatalf("parseFlags: %v", err)
	}
	if mask != flagAttested|flagSecureBoot {
		t.Fatalf("mask %#x", mask)
	}
	if _, err := parseFlags("attested,nonsense"); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if got := flagList(flagAttested | flagBPFLoaded); got != "attested,bpf" {
		t.Fatalf("flagList %q", got)
	}
}
