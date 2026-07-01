package openssltest

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCommandOKRejectsInvalidCommandOutput(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "openssl")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf \"openssl:Error: 'cmp' is an invalid command.\\n\"\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := commandOK(fake, "cmp", "-help"); err == nil {
		t.Fatal("commandOK accepted an invalid-command OpenSSL response")
	}
}
