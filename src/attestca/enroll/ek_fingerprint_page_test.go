// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek

package enroll

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/szymonwilczek/lota/attestca/internal/tpmtest"
)

// Runs the enrollment page's EK read and fingerprint steps as printed.
// The fingerprint must be the one the CA compares, and with no certificate
// the pipeline must fail rather than print a digest of nothing.

const caEnrollmentPage = "../../../Documentation/operator/production-bringup/ca-enrollment.rst"

func pageShellBlocks(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(caEnrollmentPage))
	if err != nil {
		t.Fatalf("read %s: %v", caEnrollmentPage, err)
	}
	var blocks []string
	lines := strings.Split(string(raw), "\n")
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != ".. code-block:: sh" {
			continue
		}
		var body []string
		j := i + 1
		for ; j < len(lines); j++ {
			if lines[j] != "" && !strings.HasPrefix(lines[j], "    ") {
				break
			}
			body = append(body, strings.TrimPrefix(lines[j], "    "))
		}
		blocks = append(blocks, strings.TrimSpace(strings.Join(body, "\n")))
		i = j - 1
	}
	return blocks
}

func ekReadStep(t *testing.T, blocks []string) (file, line string) {
	t.Helper()
	read := regexp.MustCompile(`tpm2_nvread\s+0x01c00002\b(.*)$`)
	for _, b := range blocks {
		for l := range strings.SplitSeq(b, "\n") {
			m := read.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			if f := regexp.MustCompile(`(?:^|\s)>\s*(\S+)`).FindStringSubmatch(m[1]); f != nil {
				return f[1], l
			}
			if f := regexp.MustCompile(`(?:^|\s)-o\s+(\S+)`).FindStringSubmatch(m[1]); f != nil {
				return f[1], l
			}
			t.Fatalf("%q writes the EK certificate nowhere the next step can name", l)
		}
	}
	t.Fatal("the page does not say how to read the EK certificate off the TPM")
	return "", ""
}

func fingerprintBlock(t *testing.T, blocks []string) string {
	t.Helper()
	for _, b := range blocks {
		if strings.Contains(b, "-modulus") && strings.Contains(b, "sha256sum") {
			return b
		}
	}
	t.Fatal("the page carries no EK fingerprint pipeline")
	return ""
}

func runPipeline(t *testing.T, dir, script string) (stdout string, err error) {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err = cmd.Run()
	return out.String(), err
}

func TestEnrollmentPageFingerprintIsTheOneTheCACompares(t *testing.T) {
	for _, tool := range []string{"sh", "openssl", "xxd", "sha256sum"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("the page's pipeline needs %s: %v", tool, err)
		}
	}

	blocks := pageShellBlocks(t)
	file, readLine := ekReadStep(t, blocks)
	pipeline := fingerprintBlock(t, blocks)

	// sudo ... -o leaves a root-owned 0660 file the operator cannot read
	if strings.Contains(readLine, "sudo") && regexp.MustCompile(`\s-o\s`).MatchString(readLine) {
		t.Errorf("%q: root creates %s, which the fingerprint step, run as the operator, cannot read; "+
			"redirect the output so the operator's shell creates it", readLine, file)
	}

	dir := t.TempDir()
	ek := tpmtest.NewEKCert(t, tpmtest.NewVendorRoot(t, "vendor-root"))
	// tpm2_nvread hands back the certificate as DER
	if err := os.WriteFile(filepath.Join(dir, file), ek.CertDER, 0o600); err != nil {
		t.Fatal(err)
	}

	want := EKFingerprint(&ek.Priv.PublicKey)
	out, err := runPipeline(t, dir, pipeline)
	if err != nil {
		t.Errorf("the pipeline fails on the %s the read step wrote: %v\n%s", file, err, pipeline)
	}
	if got := strings.Fields(out); len(got) == 0 || got[0] != want {
		t.Errorf("the page's pipeline prints %q for the certificate in %s; the CA compares %s",
			strings.TrimSpace(out), file, want)
	}

	if err := os.Remove(filepath.Join(dir, file)); err != nil {
		t.Fatal(err)
	}
	out, err = runPipeline(t, dir, pipeline)
	if err == nil {
		t.Errorf("with no %s the pipeline exits 0", file)
	}
	if regexp.MustCompile(`\b[0-9a-f]{64}\b`).MatchString(out) {
		t.Errorf("with no %s the pipeline still prints a fingerprint: %q", file, strings.TrimSpace(out))
	}
}
