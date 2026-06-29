package crypto_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/kmswrap"
)

func TestExternalKMSWrapsDEKViaCommandAdapter(t *testing.T) {
	helper := writeExternalKMSHelper(t)
	wrapper, err := kmswrap.NewExternalKMSWrapper(kmswrap.ExternalKMSConfig{
		Provider:    "awskms",
		KeyRef:      "arn:aws:kms:us-east-1:111122223333:key/trstctl-test",
		WrapCommand: helper,
		Timeout:     time.Second,
	})
	if err != nil {
		t.Fatalf("NewExternalKMSWrapper: %v", err)
	}
	if wrapper.Provider() != "awskms" || wrapper.KeyRef() == "" {
		t.Fatalf("wrapper metadata = %q/%q", wrapper.Provider(), wrapper.KeyRef())
	}

	dek := bytes.Repeat([]byte{0x42}, 32)
	wrapped, err := wrapper.WrapDEK(dek)
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if !bytes.HasPrefix(wrapped, []byte("kmswrap:")) {
		t.Fatalf("wrapped DEK does not carry external KMS envelope marker: %q", wrapped)
	}
	opened, err := wrapper.UnwrapDEK(wrapped)
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if !bytes.Equal(opened, dek) {
		t.Fatal("external KMS wrapper did not round-trip the DEK")
	}
}

func TestExternalKMSRejectsIncompleteConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  kmswrap.ExternalKMSConfig
	}{
		{name: "missing provider", cfg: kmswrap.ExternalKMSConfig{KeyRef: "key", WrapCommand: "/bin/true"}},
		{name: "missing key ref", cfg: kmswrap.ExternalKMSConfig{Provider: "awskms", WrapCommand: "/bin/true"}},
		{name: "missing command", cfg: kmswrap.ExternalKMSConfig{Provider: "awskms", KeyRef: "key"}},
		{name: "negative timeout", cfg: kmswrap.ExternalKMSConfig{Provider: "awskms", KeyRef: "key", WrapCommand: "/bin/true", Timeout: -time.Second}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := kmswrap.NewExternalKMSWrapper(tt.cfg); err == nil {
				t.Fatalf("NewExternalKMSWrapper(%+v) succeeded, want validation failure", tt.cfg)
			}
		})
	}
}

func writeExternalKMSHelper(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kmswrap.py")
	body := `#!/usr/bin/env python3
import sys

op, provider, key_ref = sys.argv[1:4]
data = sys.stdin.buffer.read()
if provider != "awskms" or not key_ref.startswith("arn:aws:kms:"):
    sys.stderr.write("bad provider or key ref")
    sys.exit(2)
if op == "wrap":
    sys.stdout.buffer.write(b"kmswrap:" + data[::-1])
elif op == "unwrap":
    if not data.startswith(b"kmswrap:"):
        sys.stderr.write("bad envelope")
        sys.exit(3)
    sys.stdout.buffer.write(data[len(b"kmswrap:"):][::-1])
else:
    sys.stderr.write("bad operation")
    sys.exit(4)
`
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatalf("write external KMS helper: %v", err)
	}
	return path
}
