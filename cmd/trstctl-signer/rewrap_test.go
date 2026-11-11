// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A200-L2: --rewrap-keystore needs the key store, the KEK that sealed it and
// the adapter it moves to, and a missing KEK is an error rather than a fresh
// key that would open nothing.
func TestRewrapKeystoreNeedsTheKEKThatSealedItA200L2(t *testing.T) {
	dir := t.TempDir()
	keystore, kekFile := filepath.Join(dir, "keys"), filepath.Join(dir, "kek.bin")
	if err := os.Mkdir(keystore, 0o700); err != nil {
		t.Fatal(err)
	}
	const keyRef = "arn:aws:kms:us-east-1:111122223333:key/signer-ca"
	for name, args := range map[string][5]string{
		"no key store": {"", kekFile, "awskms", keyRef, "/usr/local/bin/trstctl-kms-wrap"},
		"no KEK":       {keystore, "", "awskms", keyRef, "/usr/local/bin/trstctl-kms-wrap"},
		"no adapter":   {keystore, kekFile, "awskms", keyRef, ""},
	} {
		err := runRewrapKeystore(args[0], args[1], args[2], args[3], args[4], time.Second, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "--rewrap-keystore needs") {
			t.Fatalf("%s: %v, want the inputs named", name, err)
		}
	}
	err := runRewrapKeystore(keystore, kekFile, "awskms", keyRef, "/usr/local/bin/trstctl-kms-wrap", time.Second, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "load the key store's KEK") {
		t.Fatalf("missing KEK = %v, want a refusal", err)
	}
	if _, err := os.Stat(kekFile); !os.IsNotExist(err) {
		t.Fatalf("the re-wrap created a KEK in place of the missing one (%v)", err)
	}
}
