// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/signing"
)

// testAuditSigningKey is for tests that exercise buildRunDeps plumbing but do
// not exercise audit signing. Production callers never receive a local private
// key: Run and every operator command bind the signer-owned audit handle first.
func testAuditSigningKey(t *testing.T) *jose.SigningKey {
	t.Helper()
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatalf("generate test audit key: %v", err)
	}
	return key
}

// configureExternalAuditTestSigner gives command-level tests the same RPC
// boundary as an external deployment without depending on a sibling executable
// next to Go's temporary test binary. Separate-process custody is covered by
// TestAuditEvidenceOverRealSignerBinary; this helper isolates command wiring.
func configureExternalAuditTestSigner(t *testing.T, cfg *config.Config) {
	t.Helper()
	dir, err := os.MkdirTemp("", "ats-")
	if err != nil {
		t.Fatalf("create short audit signer dir: %v", err)
	}
	kekW, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("create audit signer KEK: %v", err)
	}
	srv, err := signing.NewPersistentServer(signing.NewKeyStore(filepath.Join(dir, "keys"), kekW))
	if err != nil {
		kekW.Destroy()
		_ = os.RemoveAll(dir)
		t.Fatalf("create audit signer: %v", err)
	}

	socket := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- signing.ServeServerWithOptions(ctx, socket, srv, signing.ServeOptions{
			AllowInsecureDevNonLinux: runtime.GOOS != "linux",
		})
	}()
	client, err := signing.DialReady(context.Background(), socket, 10*time.Second)
	if err != nil {
		cancel()
		serveErr := <-done
		kekW.Destroy()
		_ = os.RemoveAll(dir)
		t.Fatalf("start audit signer: dial=%v serve=%v", err, serveErr)
	}
	_ = client.Close()

	cfg.Signer.Mode = config.SignerExternal
	cfg.Signer.Socket = socket
	// External production wiring must not inherit the evaluation-only default
	// that lets the control plane read the signer's shared authorizer secret.
	// Keeping the unused path under the fixture root is a second wall if a future
	// command starts consulting it before configuration validation.
	cfg.Signer.AllowCoResidentAuthorizer = false
	cfg.Signer.AuthSecretFile = filepath.Join(dir, "unused-sign-auth.bin")
	// The external-mode preflight intentionally checks this migration path. It
	// must be absent after a successful migration, which is this test fixture's
	// fresh-deployment state.
	cfg.Audit.SigningKeyFile = filepath.Join(dir, "legacy-audit.pem")
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve audit signer: %v", err)
		}
		kekW.Destroy()
		_ = os.RemoveAll(dir)
	})
}
