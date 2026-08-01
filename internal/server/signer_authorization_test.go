// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

func testSignAuthorizer(t *testing.T) *crypto.SignAuthorizer {
	t.Helper()
	authz, err := crypto.NewSignAuthorizer(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatalf("NewSignAuthorizer: %v", err)
	}
	t.Cleanup(authz.Destroy)
	return authz
}

func serveSignerWithAuthorizer(t *testing.T, authz *crypto.SignAuthorizer) *signing.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "srvsign")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		done <- signing.ServeServerWithOptions(ctx, socket, signing.NewServer(signing.WithAuthorizer(authz)), signing.ServeOptions{AllowInsecureDevNonLinux: runtime.GOOS != "linux"})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("signer server did not stop")
		}
	})
	client, err := signing.DialReady(ctx, socket, 10*time.Second)
	if err != nil {
		t.Fatalf("DialReady signer: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestProvisionCAUsesDualControlSignerHandle(t *testing.T) {
	authz := testSignAuthorizer(t)
	client := serveSignerWithAuthorizer(t, authz)
	s := &Server{signAuthz: authz}
	ctx := context.Background()
	if err := s.provisionCA(ctx, client, "trstctl Test Issuing CA", ""); err != nil {
		t.Fatalf("provisionCA: %v", err)
	}
	if s.caSigner == nil || len(s.caCertDER) == 0 {
		t.Fatal("provisionCA did not install an issuing CA signer and certificate")
	}
	digest, err := crypto.Digest(crypto.SHA256, []byte("attested certificate body"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.caSigner.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatalf("attested CA sign through provisioned signer failed: %v", err)
	}

	forgeDigest, err := crypto.Digest(crypto.SHA256, []byte("forged certificate body"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := client.SignerForHandleWithPurpose(ctx, issuingCAHandle, signing.PurposeCASign)
	if err != nil {
		t.Fatalf("bind raw signer for issuing CA: %v", err)
	}
	_, err = raw.SignDigest(forgeDigest, crypto.SignOptions{Hash: crypto.SHA256})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("raw CA_SIGN against provisioned CA without token = %v, want PermissionDenied", status.Code(err))
	}
}

func TestProvisionCAUsesSignerAuthTokenCommand(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	authz, err := crypto.NewSignAuthorizer(secret)
	if err != nil {
		t.Fatalf("NewSignAuthorizer: %v", err)
	}
	t.Cleanup(authz.Destroy)
	client := serveSignerWithAuthorizer(t, authz)
	script := signerTokenHelperCommand(t, secret)
	s := &Server{signAuthz: newSignTokenCommand(script)}

	if err := s.provisionCA(context.Background(), client, "trstctl Test Issuing CA", ""); err != nil {
		t.Fatalf("provisionCA with signer token command: %v", err)
	}
	if s.caSigner == nil || len(s.caCertDER) == 0 {
		t.Fatal("provisionCA did not install an issuing CA signer and certificate")
	}
}

func TestPrivilegedSignerHandleRequiresIndependentTokenProvider(t *testing.T) {
	authz := testSignAuthorizer(t)
	client := serveSignerWithAuthorizer(t, authz)
	s := &Server{}

	_, err := s.generatePrivilegedKeyHandle(context.Background(), client, crypto.ECDSAP256, "blocked-ca",
		[]signing.KeyPurpose{signing.PurposeCASign}, signing.PurposeCASign)
	if !errors.Is(err, errPrivilegedSignerAuthorizationRequired) {
		t.Fatalf("privileged key generation without token provider = %v, want %v", err, errPrivilegedSignerAuthorizationRequired)
	}
}

func TestSignTokenCommandProviderReturnsExternalToken(t *testing.T) {
	token := bytes.Repeat([]byte{0xA7}, 32)
	script := filepath.Join(t.TempDir(), "approve-sign-intent.sh")
	body := "#!/bin/sh\ncat >/dev/null\nprintf '%s' '" + base64.StdEncoding.EncodeToString(token) + "'\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatalf("write token command: %v", err)
	}

	got, err := newSignTokenCommand(script).Authorize(crypto.SignIntent{
		KeyHandle: "issuing-ca",
		Purpose:   int32(signing.PurposeCASign),
		Hash:      crypto.SHA256,
		Digest:    bytes.Repeat([]byte{0x11}, 32),
	})
	if err != nil {
		t.Fatalf("Authorize via command: %v", err)
	}
	if !bytes.Equal(got, token) {
		t.Fatalf("token command returned %x, want %x", got, token)
	}
}

func TestSignerTokenCommandHelper(t *testing.T) {
	if os.Getenv("TRSTCTL_SIGNER_TOKEN_HELPER") != "1" {
		return
	}
	secret, err := base64.StdEncoding.DecodeString(os.Getenv("TRSTCTL_SIGNER_TOKEN_SECRET_B64"))
	if err != nil {
		t.Fatalf("decode helper secret: %v", err)
	}
	var req signTokenCommandIntent
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		t.Fatalf("decode signer intent: %v", err)
	}
	digest, err := base64.StdEncoding.DecodeString(req.DigestB64)
	if err != nil {
		t.Fatalf("decode signer digest: %v", err)
	}
	authz, err := crypto.NewSignAuthorizer(secret)
	if err != nil {
		t.Fatalf("NewSignAuthorizer: %v", err)
	}
	defer authz.Destroy()
	token, err := authz.Authorize(crypto.SignIntent{
		KeyHandle: req.KeyHandle,
		Purpose:   req.Purpose,
		Hash:      crypto.Hash(req.Hash),
		Padding:   crypto.RSAPadding(req.Padding),
		Digest:    digest,
	})
	if err != nil {
		t.Fatalf("authorize signer intent: %v", err)
	}
	if _, err := os.Stdout.WriteString(base64.StdEncoding.EncodeToString(token)); err != nil {
		t.Fatalf("write signer token: %v", err)
	}
	os.Exit(0)
}

func signerTokenHelperCommand(t *testing.T, secret []byte) string {
	t.Helper()
	script := filepath.Join(t.TempDir(), "signer-token-helper.sh")
	body := "#!/bin/sh\nTRSTCTL_SIGNER_TOKEN_HELPER=1 TRSTCTL_SIGNER_TOKEN_SECRET_B64='" +
		base64.StdEncoding.EncodeToString(secret) + "' '" + os.Args[0] + "' -test.run '^TestSignerTokenCommandHelper$'\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { // #nosec G306 G703 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-22, CWE-276)
		t.Fatalf("write signer token helper: %v", err)
	}
	return script
}
