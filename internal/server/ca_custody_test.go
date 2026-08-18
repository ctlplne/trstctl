// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/signing"
)

// TestProvisionCAStableAcrossSignerRestart is the R3.2 disconfirming test for the
// silent-CA-rotation finding: across a real signer restart (a fresh persistent
// signer over the same sealed key store + the persisted CA cert), the issuing CA
// certificate is byte-for-byte stable. Before R3.2 the signer regenerated the CA
// key on every restart, silently rotating the CA.
func TestProvisionCAStableAcrossSignerRestart(t *testing.T) {
	dir := t.TempDir()
	kekW, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
	if err != nil {
		t.Fatalf("LoadOrCreate KEK: %v", err)
	}
	defer kekW.Destroy()
	keysDir := filepath.Join(dir, "keys")
	socketDir, err := os.MkdirTemp("", "ts-")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(socketDir) }()
	socket := filepath.Join(socketDir, "s.sock")
	caCertFile := filepath.Join(dir, "issuing-ca.crt")

	// Boot 1: a persistent signer; the control plane provisions a fresh CA (key
	// generated in the signer + cert persisted).
	cert1 := provisionOnce(t, keysDir, kekW, socket, caCertFile)
	if len(cert1) == 0 {
		t.Fatal("boot 1 produced no CA certificate")
	}

	// Boot 2: a NEW persistent signer over the SAME sealed key store and socket
	// (the restart) — and the same persisted CA cert. The control plane must reuse
	// both, yielding an identical CA certificate.
	cert2 := provisionOnce(t, keysDir, kekW, socket, caCertFile)

	if !bytes.Equal(cert1, cert2) {
		t.Fatal("issuing CA certificate changed across a signer restart — the CA silently rotated")
	}
}

// TestProvisionCAPublishesMirrorAfterUpgrade reproduces the demo upgrade that
// first introduced a separate public-trust volume. The old persistent data
// volume still owns the authoritative certificate and the signer still owns its
// key, while the new public volume begins empty. Boot must bind the retained
// pair and publish the public copy; it must not try to generate a duplicate key.
func TestProvisionCAPublishesMirrorAfterUpgrade(t *testing.T) {
	dir := t.TempDir()
	kekW, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
	if err != nil {
		t.Fatalf("LoadOrCreate KEK: %v", err)
	}
	defer kekW.Destroy()
	keysDir := filepath.Join(dir, "keys")
	socketDir, err := os.MkdirTemp("", "ts-ca-mirror-")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(socketDir) }()
	socket := filepath.Join(socketDir, "s.sock")
	caCertFile := filepath.Join(dir, "private-data", "issuing-ca.crt")
	publicCertFile := filepath.Join(dir, "public-trust", "issuing-ca.crt")

	certBefore := provisionOnce(t, keysDir, kekW, socket, caCertFile, "")
	if _, err := os.Stat(publicCertFile); !os.IsNotExist(err) {
		t.Fatalf("public mirror unexpectedly existed before upgrade: %v", err)
	}
	certAfter := provisionOnce(t, keysDir, kekW, socket, caCertFile, publicCertFile)

	if !bytes.Equal(certBefore, certAfter) {
		t.Fatal("publishing the public mirror rotated the issuing CA")
	}
	authoritative, err := os.ReadFile(caCertFile) // #nosec G304 -- test-owned path verifies upgrade custody
	if err != nil {
		t.Fatalf("read authoritative CA certificate: %v", err)
	}
	public, err := os.ReadFile(publicCertFile) // #nosec G304 -- test-owned path verifies public mirror
	if err != nil {
		t.Fatalf("read public CA certificate mirror: %v", err)
	}
	if !bytes.Equal(authoritative, public) {
		t.Fatal("public CA certificate mirror does not exactly match the authoritative certificate")
	}
}

func TestProvisionCARefusesIncompleteOrMismatchedCustody(t *testing.T) {
	t.Run("retained key without authoritative certificate", func(t *testing.T) {
		dir := t.TempDir()
		kekW, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
		if err != nil {
			t.Fatal(err)
		}
		defer kekW.Destroy()
		keysDir := filepath.Join(dir, "keys")
		socketDir, err := os.MkdirTemp("", "ts-ca-missing-")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.RemoveAll(socketDir) }()
		socket := filepath.Join(socketDir, "s.sock")
		caCertFile := filepath.Join(dir, "private-data", "issuing-ca.crt")
		publicCertFile := filepath.Join(dir, "public-trust", "issuing-ca.crt")
		_ = provisionOnce(t, keysDir, kekW, socket, caCertFile)
		if err := os.Remove(caCertFile); err != nil {
			t.Fatal(err)
		}

		_, err = provisionAttempt(t, keysDir, kekW, socket, caCertFile, publicCertFile)
		if err == nil || !strings.Contains(err.Error(), "exists") || !strings.Contains(err.Error(), "refusing implicit trust replacement") {
			t.Fatalf("missing authoritative certificate error = %v, want fail-closed retained-key refusal", err)
		}
		if _, statErr := os.Stat(publicCertFile); !os.IsNotExist(statErr) {
			t.Fatalf("public mirror was published from incomplete custody: %v", statErr)
		}
	})

	t.Run("certificate for another key", func(t *testing.T) {
		dir := t.TempDir()
		kekW, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
		if err != nil {
			t.Fatal(err)
		}
		defer kekW.Destroy()
		keysDir := filepath.Join(dir, "keys")
		socketDir, err := os.MkdirTemp("", "ts-ca-mismatch-")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.RemoveAll(socketDir) }()
		socket := filepath.Join(socketDir, "s.sock")
		caCertFile := filepath.Join(dir, "private-data", "issuing-ca.crt")
		_ = provisionOnce(t, keysDir, kekW, socket, caCertFile)

		other, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		defer other.Destroy()
		mismatchedDER, err := crypto.SelfSignedCACert(other, "Unrelated CA", 24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeCertPEM(caCertFile, mismatchedDER); err != nil {
			t.Fatal(err)
		}

		_, err = provisionAttempt(t, keysDir, kekW, socket, caCertFile, "")
		if err == nil || !strings.Contains(err.Error(), "does not match") || !strings.Contains(err.Error(), "refusing trust rotation") {
			t.Fatalf("mismatched issuing CA error = %v, want fail-closed key/certificate refusal", err)
		}
	})
}

// TestProvisionAgentCARecoversMissingCertificateFromPersistedHandle is the
// AUD-100 pre-fix container-recreation shape. The public certificate used to be
// written into the disposable container layer while the private key correctly
// survived in the signer volume. Recovery must bind the retained handle and
// restore public material for that same key; it must never rotate agent trust.
func TestProvisionAgentCARecoversMissingCertificateFromPersistedHandle(t *testing.T) {
	dir := t.TempDir()
	kekW, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
	if err != nil {
		t.Fatalf("LoadOrCreate KEK: %v", err)
	}
	defer kekW.Destroy()
	keysDir := filepath.Join(dir, "keys")
	socketDir, err := os.MkdirTemp("", "ts-agent-")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(socketDir) }()
	socket := filepath.Join(socketDir, "s.sock")
	caCertFile := filepath.Join(dir, "agent-ca.crt")

	cert1 := provisionAgentOnce(t, keysDir, kekW, socket, caCertFile)
	public1, err := crypto.PublicKeyDERFromCert(cert1)
	if err != nil {
		t.Fatalf("boot 1 agent CA public key: %v", err)
	}
	if err := os.Remove(caCertFile); err != nil {
		t.Fatalf("plant pre-fix orphaned agent CA state: %v", err)
	}

	cert2 := provisionAgentOnce(t, keysDir, kekW, socket, caCertFile)
	public2, err := crypto.PublicKeyDERFromCert(cert2)
	if err != nil {
		t.Fatalf("recovered agent CA public key: %v", err)
	}
	if !bytes.Equal(public1, public2) {
		t.Fatal("orphaned agent CA recovery rotated the signer key instead of retaining agent trust")
	}
	if _, err := os.Stat(caCertFile); err != nil {
		t.Fatalf("recovered agent CA certificate was not persisted: %v", err)
	}
}

func TestProvisionAgentCARefusesMalformedOrMismatchedCertificate(t *testing.T) {
	t.Run("malformed certificate is preserved", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "agent-ca.crt")
		planted := []byte("not a certificate\n")
		if err := os.WriteFile(path, planted, 0o600); err != nil {
			t.Fatal(err)
		}
		err := (&Server{}).provisionAgentCA(context.Background(), &signing.Client{}, path)
		if err == nil || !strings.Contains(err.Error(), "invalid") || !strings.Contains(err.Error(), "refusing to overwrite") {
			t.Fatalf("malformed certificate error = %v, want actionable fail-closed refusal", err)
		}
		after, readErr := os.ReadFile(path) // #nosec G304 -- test-owned path under t.TempDir verifies fail-closed preservation (CWE-22)
		if readErr != nil || !bytes.Equal(after, planted) {
			t.Fatalf("malformed certificate was changed: bytes=%q err=%v", after, readErr)
		}
	})

	t.Run("certificate for another key is preserved", func(t *testing.T) {
		dir := t.TempDir()
		kekW, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
		if err != nil {
			t.Fatal(err)
		}
		defer kekW.Destroy()
		keysDir := filepath.Join(dir, "keys")
		socketDir, err := os.MkdirTemp("", "ts-agent-mismatch-")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.RemoveAll(socketDir) }()
		socket := filepath.Join(socketDir, "s.sock")
		path := filepath.Join(dir, "agent-ca.crt")
		_ = provisionAgentOnce(t, keysDir, kekW, socket, path)

		other, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		defer other.Destroy()
		mismatchedDER, err := crypto.SelfSignedCACert(other, "trstctl Agent CA", 90*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeCertPEM(path, mismatchedDER); err != nil {
			t.Fatal(err)
		}
		planted, err := os.ReadFile(path) // #nosec G304 -- test-owned path under t.TempDir captures the planted mismatch (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		_, err = provisionAgentAttempt(t, keysDir, kekW, socket, path)
		if err == nil || !strings.Contains(err.Error(), "does not match") || !strings.Contains(err.Error(), "refusing trust rotation") {
			t.Fatalf("mismatched certificate error = %v, want actionable fail-closed refusal", err)
		}
		after, readErr := os.ReadFile(path) // #nosec G304 -- same test-owned path proves the mismatch was not overwritten (CWE-22)
		if readErr != nil || !bytes.Equal(after, planted) {
			t.Fatalf("mismatched certificate was changed: equal=%t err=%v", bytes.Equal(after, planted), readErr)
		}
	})
}

// provisionOnce starts a persistent signer over the given sealed key store +
// socket, has a control-plane Server provision the issuing CA against it, and
// returns the CA certificate PEM. The signer is stopped before returning, so the
// next call is a genuine restart over the same persisted keys.
func provisionOnce(t *testing.T, keysDir string, kekW *seal.LocalKEK, socket, caCertFile string, caPublicCertFile ...string) []byte {
	t.Helper()
	publicCertFile := ""
	if len(caPublicCertFile) > 0 {
		publicCertFile = caPublicCertFile[0]
	}
	cert, err := provisionAttempt(t, keysDir, kekW, socket, caCertFile, publicCertFile)
	if err != nil {
		t.Fatalf("provisionCA: %v", err)
	}
	return cert
}

func provisionAttempt(t *testing.T, keysDir string, kekW *seal.LocalKEK, socket, caCertFile, caPublicCertFile string) ([]byte, error) {
	t.Helper()
	ks := signing.NewKeyStore(keysDir, kekW)
	authz, err := crypto.NewSignAuthorizer(bytes.Repeat([]byte{0x5A}, 32))
	if err != nil {
		t.Fatalf("NewSignAuthorizer: %v", err)
	}
	defer authz.Destroy()
	srv, err := signing.NewPersistentServer(ks, signing.WithAuthorizer(authz))
	if err != nil {
		t.Fatalf("NewPersistentServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = signing.ServeServerWithOptions(ctx, socket, srv, signing.ServeOptions{AllowInsecureDevNonLinux: runtime.GOOS != "linux"})
	}()
	defer func() { cancel(); <-done }()

	client, err := signing.DialReady(context.Background(), socket, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial signer: %w", err)
	}
	defer func() { _ = client.Close() }()

	s := &Server{signAuthz: authz}
	if err := s.provisionCA(ctx, client, "", caCertFile, caPublicCertFile); err != nil {
		return nil, err
	}
	return s.CACertPEM(), nil
}

func provisionAgentOnce(t *testing.T, keysDir string, kekW *seal.LocalKEK, socket, caCertFile string) []byte {
	t.Helper()
	cert, err := provisionAgentAttempt(t, keysDir, kekW, socket, caCertFile)
	if err != nil {
		t.Fatalf("provisionAgentCA: %v", err)
	}
	return cert
}

func provisionAgentAttempt(t *testing.T, keysDir string, kekW *seal.LocalKEK, socket, caCertFile string) ([]byte, error) {
	t.Helper()
	ks := signing.NewKeyStore(keysDir, kekW)
	authz, err := crypto.NewSignAuthorizer(bytes.Repeat([]byte{0x6A}, 32))
	if err != nil {
		t.Fatalf("NewSignAuthorizer: %v", err)
	}
	defer authz.Destroy()
	srv, err := signing.NewPersistentServer(ks, signing.WithAuthorizer(authz))
	if err != nil {
		t.Fatalf("NewPersistentServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = signing.ServeServerWithOptions(ctx, socket, srv, signing.ServeOptions{AllowInsecureDevNonLinux: runtime.GOOS != "linux"})
	}()
	defer func() { cancel(); <-done }()

	client, err := signing.DialReady(context.Background(), socket, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial signer: %w", err)
	}
	defer func() { _ = client.Close() }()

	s := &Server{signAuthz: authz}
	if err := s.provisionAgentCA(ctx, client, caCertFile); err != nil {
		return nil, err
	}
	return bytes.Clone(s.agentCACertDER), nil
}
