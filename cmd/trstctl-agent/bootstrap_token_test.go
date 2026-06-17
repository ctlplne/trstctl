package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/mtls"
)

func TestBootstrapTokenFileLoadsTrimmedToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap-token")
	if err := os.WriteFile(path, []byte("  trst_bootstrap_secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := bootstrapToken(agentOptions{tokenFile: path})
	if err != nil {
		t.Fatalf("bootstrapToken(token file): %v", err)
	}
	if got != "trst_bootstrap_secret" {
		t.Fatalf("token = %q, want trimmed token", got)
	}
}

func TestBootstrapTokenRejectsAmbiguousSources(t *testing.T) {
	_, err := bootstrapToken(agentOptions{token: "inline", tokenFile: "token-file"})
	if err == nil {
		t.Fatal("bootstrapToken accepted both --bootstrap-token and --bootstrap-token-file")
	}
}

func TestBootstrapTokenFileNotRequiredAfterIdentityPersisted(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "agent.key")
	certPath := filepath.Join(dir, "agent.crt")
	if err := os.WriteFile(keyPath, []byte("persisted key placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, []byte("persisted cert placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := bootstrapTokenForRun(agentOptions{
		tokenFile: filepath.Join(dir, "deleted-after-first-boot-token"),
		keyPath:   keyPath,
		certPath:  certPath,
	})
	if err != nil {
		t.Fatalf("persisted identity should not require bootstrap token file: %v", err)
	}
	if got != "" {
		t.Fatalf("token = %q, want empty because persisted identity reload does not re-enroll", got)
	}
}

func TestAgentBootstrapPinsCABundle(t *testing.T) {
	serverCert, err := mtls.SelfSignedServerCert([]string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	client, err := enrollmentHTTPClient(serverCert.TrustPEM)
	if err != nil {
		t.Fatalf("enrollmentHTTPClient(valid CA): %v", err)
	}
	if client.Transport == nil {
		t.Fatal("enrollmentHTTPClient returned client without explicit transport")
	}
	if _, err := enrollmentHTTPClient([]byte("not a certificate")); err == nil {
		t.Fatal("enrollmentHTTPClient accepted an invalid CA bundle")
	}
}
