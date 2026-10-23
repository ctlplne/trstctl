// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/testutil/openssltest"
)

// The key ceremony runbook tells an offline root's custodians to prove
// possession with these exact OpenSSL commands; they must produce what
// VerifyOfflinePossession accepts, for every family an offline root can use.
func TestOfflinePossessionRunbookOpenSSLCommands(t *testing.T) {
	openssl := openssltest.RequireAny(t)
	dir := t.TempDir()
	const ceremony = "3f2a9c1e-7b4d-4e8a-9c0f-5d6e7f809a1b"
	run := func(t *testing.T, name string, args ...string) error {
		t.Helper()
		cmd := exec.Command(name, args...) // #nosec G204 -- the test's own openssl binary and fixed arguments (CWE-78)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			return &possessionCommandError{args: append([]string{name}, args...), out: string(out), err: err}
		}
		return nil
	}

	// Step 1 of the runbook: the challenge bytes.
	message := filepath.Join(dir, "possession-message.bin")
	if err := run(t, "sh", "-c", `printf 'trstctl offline root proof of possession v1\000%s' "$1" > "$2"`, "sh", ceremony, message); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(message) // #nosec G304 -- the test's own temporary file (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(written, OfflinePossessionMessage(ceremony)) {
		t.Fatalf("printf wrote %q, want %q", written, OfflinePossessionMessage(ceremony))
	}

	dgstSign := [][]string{{"dgst", "-sha256", "-sign", "root-key.pem", "-out", "possession.sig", "possession-message.bin"}}
	rawSign := [][]string{{"pkeyutl", "-sign", "-inkey", "root-key.pem", "-rawin", "-in", "possession-message.bin", "-out", "possession.sig"}}
	digestThenRaw := [][]string{
		{"dgst", "-sha256", "-binary", "-out", "possession-digest.bin", "possession-message.bin"},
		{"pkeyutl", "-sign", "-inkey", "root-key.pem", "-rawin", "-in", "possession-digest.bin", "-out", "possession.sig"},
	}
	for _, tc := range []struct {
		name     string
		genpkey  []string
		sign     [][]string
		optional bool
	}{
		{"ECDSA P-384", []string{"-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"}, dgstSign, false},
		{"RSA-3072", []string{"-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"}, dgstSign, false},
		{"Ed25519", []string{"-algorithm", "ED25519"}, rawSign, false},
		{"ML-DSA-65", []string{"-algorithm", "ML-DSA-65"}, digestThenRaw, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := run(t, openssl, append([]string{"genpkey", "-out", "root-key.pem"}, tc.genpkey...)...); err != nil {
				if tc.optional && strings.Contains(err.Error(), "ML-DSA") {
					t.Skipf("this OpenSSL has no ML-DSA: %v", err)
				}
				t.Fatal(err)
			}
			if err := run(t, openssl, "req", "-x509", "-new", "-key", "root-key.pem", "-subj", "/CN=Offline "+tc.name+" Root",
				"-days", "30", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
				"-outform", "DER", "-out", "root.der"); err != nil {
				t.Fatal(err)
			}
			for _, step := range tc.sign {
				if err := run(t, openssl, step...); err != nil {
					t.Fatal(err)
				}
			}
			rootDER, err := os.ReadFile(filepath.Join(dir, "root.der")) // #nosec G304 -- the test's own temporary file (CWE-22)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := os.ReadFile(filepath.Join(dir, "possession.sig")) // #nosec G304 -- the test's own temporary file (CWE-22)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyOfflinePossession(rootDER, ceremony, sig); err != nil {
				t.Fatalf("%s: the runbook's signature does not verify: %v", tc.name, err)
			}
			if err := VerifyOfflinePossession(rootDER, "another-ceremony", sig); err == nil {
				t.Fatalf("%s: a signature verified for another ceremony", tc.name)
			}
		})
	}
}

type possessionCommandError struct {
	args []string
	out  string
	err  error
}

func (e *possessionCommandError) Error() string {
	return strings.Join(e.args, " ") + ": " + e.err.Error() + ": " + strings.TrimSpace(e.out)
}
