// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/szymonwilczek/lota/verifier/metrics"
	"github.com/szymonwilczek/lota/verifier/store"
	"github.com/szymonwilczek/lota/verifier/types"
	"github.com/szymonwilczek/lota/verifier/verify"
)

// Runs the enrollment page's re-anchor and delete examples as curl would:
// over TLS trusting only --cacert, shell variables expanded, against the real
// handlers. The response must match the one the page prints.

const enrollmentPage = "../../../Documentation/operator/production-bringup/ca-enrollment.rst"

// code-block language and dedented text
type rstBlock struct {
	lang string
	text string
}

func rstBlocks(t *testing.T, path string) []rstBlock {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	directive := regexp.MustCompile(`^\.\. code-block:: *(\S+)`)

	var blocks []rstBlock
	lines := strings.Split(string(raw), "\n")
	for i := 0; i < len(lines); i++ {
		m := directive.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		var body []string
		j := i + 1
		for ; j < len(lines); j++ {
			l := lines[j]
			if l == "" || strings.HasPrefix(l, "    ") {
				body = append(body, strings.TrimPrefix(l, "    "))
				continue
			}
			break
		}
		blocks = append(blocks, rstBlock{
			lang: m[1],
			text: strings.TrimSpace(strings.Join(body, "\n")),
		})
		i = j - 1
	}
	return blocks
}

// shellWords splits cmd as sh does for the quoting the page uses:
// backslash-newline joins, single quotes are literal, $NAME expands from env
// elsewhere. A name env lacks is an error: the page never sets it.
func shellWords(t *testing.T, cmd string, env map[string]string) []string {
	t.Helper()
	cmd = strings.ReplaceAll(cmd, "\\\n", " ")

	var words []string
	var cur strings.Builder
	inWord := false
	expand := func(s string, i int) int {
		j := i + 1
		for j < len(s) && (s[j] == '_' || s[j] >= 'A' && s[j] <= 'Z' ||
			s[j] >= 'a' && s[j] <= 'z' || s[j] >= '0' && s[j] <= '9') {
			j++
		}
		name := s[i+1 : j]
		v, ok := env[name]
		if !ok {
			t.Errorf("the command uses $%s, which the page does not say how to set", name)
		}
		cur.WriteString(v)
		return j
	}
	for i := 0; i < len(cmd); {
		c := cmd[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
			i++
		case c == '\'':
			end := strings.IndexByte(cmd[i+1:], '\'')
			if end < 0 {
				t.Fatalf("unterminated single quote in %q", cmd)
			}
			cur.WriteString(cmd[i+1 : i+1+end])
			inWord = true
			i += end + 2
		case c == '"':
			inWord = true
			i++
			for i < len(cmd) && cmd[i] != '"' {
				if cmd[i] == '$' {
					i = expand(cmd, i)
					continue
				}
				cur.WriteByte(cmd[i])
				i++
			}
			if i >= len(cmd) {
				t.Fatalf("unterminated double quote in %q", cmd)
			}
			i++
		case c == '$':
			inWord = true
			i = expand(cmd, i)
		default:
			inWord = true
			cur.WriteByte(c)
			i++
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words
}

type curlCall struct {
	method  string
	target  string
	headers http.Header
	data    string
	cacert  string
}

func parseCurl(t *testing.T, words []string) curlCall {
	t.Helper()
	call := curlCall{method: http.MethodGet, headers: http.Header{}}
	for i := 1; i < len(words); i++ {
		w := words[i]
		next := func() string {
			i++
			if i >= len(words) {
				t.Fatalf("curl option %s has no value", w)
			}
			return words[i]
		}
		switch w {
		case "-X", "--request":
			call.method = next()
		case "-H", "--header":
			k, v, ok := strings.Cut(next(), ":")
			if !ok {
				t.Fatalf("header %q has no colon", words[i])
			}
			call.headers.Add(strings.TrimSpace(k), strings.TrimSpace(v))
		case "-d", "--data":
			call.data = next()
			if call.method == http.MethodGet {
				call.method = http.MethodPost
			}
		case "--cacert":
			call.cacert = next()
		default:
			if strings.HasPrefix(w, "-") {
				t.Fatalf("curl option %s is not one this test knows how to run", w)
			}
			call.target = w
		}
	}
	return call
}

func TestEnrollmentPageLifecycleExamplesRunAsPrinted(t *testing.T) {
	const (
		clientID = "4f0c2a1d9be85f3e7a6d0c1b2e3f4a5b6c7d8e9f0a1b2c3d4e5f60718293a4b5"
		adminKey = "admin-key"
	)

	bs := verify.NewBaselineStore()
	m := metrics.New()
	cfg := verify.DefaultConfig()
	cfg.RequireBootEnrollment = false
	cfg.BaselineStore = bs
	cfg.Metrics = m
	v := verify.NewVerifier(cfg, newCertStore(t))
	srv := &Server{verifier: v, addr: ":8443"}
	auditLog := store.NewMemoryAuditLog()
	mux := http.NewServeMux()
	NewAPIHandler(mux, v, srv, auditLog, nil, m,
		store.NewMemoryAttestationLog(), adminKey, "reader-key")

	// off-host the API is HTTPS under a deployment CA no system store holds
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()
	listener, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	env := map[string]string{
		"LOTA_ADMIN_API_KEY": adminKey,
		"CLIENT_ID":          clientID,
	}

	blocks := rstBlocks(t, enrollmentPage)
	ran := 0
	for i, b := range blocks {
		if b.lang != "sh" || !strings.HasPrefix(b.text, "curl ") {
			continue
		}
		ran++
		words := shellWords(t, b.text, env)
		call := parseCurl(t, words)

		// curl globs braces: {placeholder} is sent as its bare name
		if strings.ContainsAny(call.target, "{}") {
			t.Errorf("%q: curl sends the braces' contents literally; the client ID never reaches the verifier",
				call.target)
			continue
		}
		u, err := url.Parse(call.target)
		if err != nil {
			t.Fatalf("parse %q: %v", call.target, err)
		}
		if u.Scheme != "https" {
			t.Errorf("%q: off the verifier's host the API only answers HTTPS", call.target)
			continue
		}

		// the page's host is the verifier; dial the listener, as --resolve
		roots := x509.NewCertPool()
		if call.cacert != "" {
			roots.AddCert(ts.Certificate())
		} else if sys, err := x509.SystemCertPool(); err == nil {
			roots = sys
		}
		client := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12,
				ServerName: "example.com"},
		}}
		u.Host = listener.Host

		// each call needs a pinned baseline; a failed call left its own
		var before [types.HashSize]byte
		before[0] = 0x11
		if res, _ := bs.CheckAndUpdate(clientID, before); res != verify.TOFUFirstUse &&
			res != verify.TOFUMatch {
			t.Fatalf("seeding %s: %v", clientID, res)
		}

		req, err := http.NewRequest(call.method, u.String(), strings.NewReader(call.data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header = call.headers
		// curl -d's default; the handlers parse JSON regardless
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("%s %s: %v -- without --cacert naming the verifier's issuing CA the TLS handshake fails",
				call.method, call.target, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s %s: status %d -- %s", call.method, call.target, resp.StatusCode, body)
			continue
		}

		// the block under the command is its response
		if i+1 >= len(blocks) || blocks[i+1].lang != "json" {
			t.Errorf("%s %s: the page shows no response under the command; the verifier answered %s",
				call.method, call.target, bytes.TrimSpace(body))
			continue
		}
		printed := strings.ReplaceAll(blocks[i+1].text, "<client-id>", clientID)
		var want, got any
		if err := json.Unmarshal([]byte(printed), &want); err != nil {
			t.Fatalf("the response the page prints is not JSON: %v\n%s", err, printed)
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		if !jsonEqual(want, got) {
			t.Errorf("%s %s: page prints %s, verifier answered %s",
				call.method, call.target, printed, bytes.TrimSpace(body))
		}
	}
	if ran != 2 {
		t.Fatalf("ran %d curl examples from the page, want the re-anchor and the delete", ran)
	}

	for _, e := range auditLog.Query(10) {
		if e.Reason == "" || e.Actor == "" {
			t.Errorf("audit entry %s for %s carries no actor or reason", e.Action, e.TargetID)
		}
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
