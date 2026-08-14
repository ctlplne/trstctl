// SPDX-License-Identifier: LicenseRef-trstctl-EE

package pqc

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// TestSignerBinarySignsPQCOverUDS is the PQC-01 served-path acceptance test:
// post-quantum keys must be generated inside the isolated signer process and
// used through the UDS Sign RPC. The signer RPC accepts pre-computed digests, so
// the PQC verifier checks the exact digest bytes that crossed the AN-4 boundary.
func TestSignerBinarySignsPQCOverUDS(t *testing.T) {
	bin := buildSigner(t)
	dir, err := os.MkdirTemp("", "pqc")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	socket := filepath.Join(dir, "s.sock")

	ctx := context.Background()
	client, stop, err := signing.StartChild(ctx, bin, socket, devSignerArgs()...)
	if err != nil {
		t.Fatalf("StartChild: %v", err)
	}
	defer stop()
	defer func() { _ = client.Close() }()

	digest, err := crypto.Digest(crypto.SHA256, []byte("PQC-01 served signer known vector"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		algorithm crypto.Algorithm
		verify    func(crypto.PublicKey, []byte, []byte) error
	}{
		{
			name:      "ml-dsa-44",
			algorithm: MLDSA44,
			verify:    Verify,
		},
		{
			name:      "slh-dsa-sha2-128f",
			algorithm: SLHDSA128f,
			verify:    VerifySLHDSA,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := client.GenerateLicensedKeyHandle(ctx, protoFromAlgorithm(tt.algorithm), tt.algorithm, "", nil, signing.PurposeGeneric)
			if err != nil {
				t.Fatalf("GenerateKey(%s): %v", tt.algorithm, err)
			}
			if got := signer.Algorithm(); got != tt.algorithm {
				t.Fatalf("remote signer algorithm = %s, want %s", got, tt.algorithm)
			}

			sig, err := signer.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256})
			if err != nil {
				t.Fatalf("SignDigest(%s): %v", tt.algorithm, err)
			}
			if err := tt.verify(signer.Public(), digest, sig); err != nil {
				t.Fatalf("verify %s signature from signer process: %v", tt.algorithm, err)
			}
		})
	}
}

func protoFromAlgorithm(alg crypto.Algorithm) signerpb.Algorithm {
	return signerKeyFactory{}.ProtoFromAlgorithm(alg)
}

func buildSigner(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "trstctl-signer")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/trstctl-signer") // #nosec G204 -- executable and argv are fixed; output is confined to TempDir (CWE-78).
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build trstctl-signer: %v\n%s", err, out)
	}
	return bin
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func devSignerArgs(extra ...string) []string {
	if runtime.GOOS == "linux" {
		return extra
	}
	return append([]string{"--allow-insecure-dev-nonlinux"}, extra...)
}
