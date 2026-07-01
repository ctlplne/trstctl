package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	if !bytes.Equal(got, []byte("trst_bootstrap_secret")) {
		t.Fatalf("token = %q, want trimmed token", got)
	}
}

func TestBootstrapTokenRejectsInlineArg(t *testing.T) {
	_, err := bootstrapToken(agentOptions{inlineToken: "inline-secret"})
	if err == nil {
		t.Fatal("bootstrapToken accepted an inline bootstrap token without the explicit development override")
	}
	if !strings.Contains(err.Error(), "--bootstrap-token-file") {
		t.Fatalf("error = %v, want token-file guidance", err)
	}
}

func TestBootstrapTokenRejectsAmbiguousSources(t *testing.T) {
	_, err := bootstrapToken(agentOptions{
		inlineToken:                       "inline",
		tokenFile:                         "token-file",
		allowInsecureDevBootstrapTokenArg: true,
	})
	if err == nil {
		t.Fatal("bootstrapToken accepted both inline and file bootstrap token sources")
	}
}

func TestServiceArgumentsNeverPersistInlineBootstrapToken(t *testing.T) {
	args := serviceArguments(agentOptions{
		enrollURL:   "https://cp.example/enroll",
		caBundle:    "/etc/trstctl/ca.pem",
		serverAddr:  "cp.example:9443",
		commonName:  "win-agent-1",
		keyPath:     "C:\\ProgramData\\trstctl\\agent.key",
		certPath:    "C:\\ProgramData\\trstctl\\agent.crt",
		rotateEvery: time.Hour,
		inlineToken: "inline-secret",
		tokenFile:   "C:\\ProgramData\\trstctl\\bootstrap-token.txt",
	})
	joined := strings.Join(args, "\x00")
	if strings.Contains(joined, "inline-secret") || strings.Contains(joined, "--bootstrap-token\x00") {
		t.Fatalf("service arguments persisted inline bootstrap token: %q", args)
	}
	if !strings.Contains(joined, "--bootstrap-token-file\x00C:\\ProgramData\\trstctl\\bootstrap-token.txt") {
		t.Fatalf("service arguments did not preserve the bootstrap token file path: %q", args)
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
	if len(got) != 0 {
		t.Fatalf("token = %q, want empty because persisted identity reload does not re-enroll", got)
	}
}

func TestAgentK8sIdentityFlagsAreExposed(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "--help")
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=readonly")
	out, _ := cmd.CombinedOutput()
	help := string(out)
	for _, want := range []string{
		"-key string",
		"-cert string",
		"-prepare-identity-dir string",
		"-prepare-identity-uid int",
		"-prepare-identity-gid int",
		"-k8s",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("trstctl-agent --help missing %q; output:\n%s", want, help)
		}
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
