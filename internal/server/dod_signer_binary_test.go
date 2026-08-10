// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

type dodShippedSignerLicense struct {
	file             string
	trustedPublicKey []byte
}

type dodShippedSignerProcess struct {
	t             *testing.T
	socket        string
	tokenProvider signing.SignTokenProvider
	stderr        *bytes.Buffer
}

func (p *dodShippedSignerProcess) connect() runSigner {
	p.t.Helper()
	client, err := signing.DialReady(context.Background(), p.socket, 10*time.Second)
	if err != nil {
		p.t.Fatalf("dial shipped trstctl-signer: %v; stderr=%s", err, p.stderr.String())
	}
	p.t.Cleanup(func() { _ = client.Close() })
	return runSigner{signer: signing.StaticProvider{C: client}, tokenProvider: p.tokenProvider}
}

// dodStartShippedSignerProcess builds cmd/trstctl-signer and launches that exact
// shipped program with its production flags. Runtime proofs use this shared seam
// so they cover main's hardening, auth-secret, persistent-keystore, managed-key
// attach, and UDS startup path rather than a test-binary helper server.
func dodStartShippedSignerProcess(t *testing.T, dir, label, authFile, managedKeysConfig string, tokenProvider signing.SignTokenProvider, licenses ...dodShippedSignerLicense) runSigner {
	t.Helper()
	first, _ := dodStartRestartableShippedSignerProcess(t, dir, label, authFile, managedKeysConfig, tokenProvider, licenses...)
	return first
}

// dodStartRestartableShippedSignerProcess models a control-plane restart against
// one persistent external signer process. Each call to reconnect returns a new
// gRPC Client with no stale admission hook from the previous Server. That is the
// production lifecycle: Run opens a connection, Build binds that connection to
// its own signing pool, and shutdown closes the connection before a new Run.
func dodStartRestartableShippedSignerProcess(t *testing.T, dir, label, authFile, managedKeysConfig string, tokenProvider signing.SignTokenProvider, licenses ...dodShippedSignerLicense) (runSigner, func() runSigner) {
	t.Helper()
	if len(licenses) > 1 {
		t.Fatal("shipped signer proof accepts at most one license fixture")
	}
	binary := filepath.Join(dir, label+"-trstctl-signer")
	workingDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("signer proof working directory: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(workingDir, "../.."))
	buildArgs := []string{"build"}
	if len(licenses) == 1 {
		if licenses[0].file == "" || len(licenses[0].trustedPublicKey) == 0 {
			t.Fatal("shipped signer proof license fixture is incomplete")
		}
		trustedKey := base64.StdEncoding.EncodeToString(licenses[0].trustedPublicKey)
		buildArgs = append(buildArgs, "-ldflags", "-X trstctl.com/trstctl/internal/license.builtinPubKeysB64="+trustedKey)
	}
	buildArgs = append(buildArgs, "-o", binary, "./cmd/trstctl-signer")
	build := exec.Command("go", buildArgs...)
	build.Dir = repoRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build shipped trstctl-signer: %v\n%s", err, output)
	}

	socketDir, err := os.MkdirTemp("", "trstctl-dod-shipped-signer-")
	if err != nil {
		t.Fatalf("create signer socket directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "s.sock")
	args := []string{
		"--socket", socket,
		"--keystore", filepath.Join(dir, label+"-keys"),
		"--kek", filepath.Join(dir, label+"-kek.bin"),
		"--auth-secret", authFile,
	}
	if managedKeysConfig != "" {
		args = append(args, "--managed-keys-config", managedKeysConfig)
	}
	if len(licenses) == 1 {
		args = append(args, "--license", licenses[0].file)
	}
	if runtime.GOOS != "linux" {
		args = append(args, "--allow-insecure-dev-nonlinux")
	}
	cmd := exec.Command(binary, args...) // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
	cmd.Stdout = io.Discard
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start shipped trstctl-signer: %v", err)
	}
	stopped := false
	t.Cleanup(func() {
		if stopped {
			return
		}
		stopped = true
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("shipped trstctl-signer process: %v; stderr=%s", err, stderr.String())
			}
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Error("shipped trstctl-signer did not stop")
		}
	})

	process := &dodShippedSignerProcess{t: t, socket: socket, tokenProvider: tokenProvider, stderr: stderr}
	first := process.connect()
	return first, process.connect
}

func TestShippedSignerBinaryProofHelperUsesProductionMain(t *testing.T) {
	dir := t.TempDir()
	authFile := filepath.Join(dir, "signer-auth.bin")
	authorizer, err := signing.LoadOrCreateAuthorizer(authFile)
	if err != nil {
		t.Fatalf("load proof authorizer: %v", err)
	}
	t.Cleanup(authorizer.Destroy)
	run := dodStartShippedSignerProcess(t, dir, "startup-proof", authFile, "", authorizer)
	client := run.signer.Client()
	ctx := context.Background()
	remote, err := client.GenerateDualControlKeyHandle(ctx, crypto.ECDSAP256,
		"shipped-binary-proof-key", []signing.KeyPurpose{signing.PurposeCodeSign},
		signing.PurposeCodeSign, authorizer)
	if err != nil {
		t.Fatalf("generate dual-control key through shipped binary: %v", err)
	}
	digest := crypto.SHA256Sum([]byte("shipped signer binary startup proof"))
	first, err := remote.SignDigestForOperation("shipped-binary-operation", digest,
		crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("sign through shipped binary: %v", err)
	}
	replay, err := remote.SignDigestForOperation("shipped-binary-operation", digest,
		crypto.SignOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("replay through shipped binary: %v", err)
	}
	if !bytes.Equal(first, replay) {
		t.Fatal("shipped signer binary did not replay its exact journaled signature")
	}
}
