// SPDX-License-Identifier: BUSL-1.1

package signing_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

// A200-L2 restore drill against the real binary: a signer serving from a
// local-KEK key store makes two keys; trstctl-signer --rewrap-keystore moves
// the store onto the external KMS wrap command; the signer then serves the
// same keys from the re-wrapped store without --kek, signing digests the
// original public keys verify; the local KEK no longer starts it; and the
// rollback copy still does.
func TestSignerBinaryRewrapsALocalKEKKeyStoreOntoTheKMSAdapterA200L2(t *testing.T) {
	bin := buildSigner(t)
	dir, err := os.MkdirTemp("", "rewrap")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	keystore, kekFile := filepath.Join(dir, "keys"), filepath.Join(dir, "kek.bin")
	helper := writeSignerKMSHelper(t)
	const keyRef = "arn:aws:kms:us-east-1:111122223333:key/signer-ca"
	kms := []string{"--kms-provider", "awskms", "--kms-key-ref", keyRef, "--kms-wrap-command", helper, "--kms-timeout", "5s"}
	ctx := context.Background()
	start := func(socket string, args ...string) (*signing.Client, func(), error) {
		return signing.StartChild(ctx, bin, filepath.Join(dir, socket), devSignerArgs(args...)...)
	}

	client, stop, err := start("a.sock", "--keystore", keystore, "--kek", kekFile)
	if err != nil {
		t.Fatalf("local-KEK signer: %v", err)
	}
	handles := []string{"rewrap-ca", "rewrap-issuing"}
	publics := map[string]crypto.PublicKey{}
	for _, handle := range handles {
		signer, err := client.GenerateKeyHandle(ctx, crypto.ECDSAP256, handle)
		if err != nil {
			t.Fatalf("generate %s: %v", handle, err)
		}
		publics[handle] = signer.Public()
	}
	_ = client.Close()
	stop()

	out, err := exec.Command(bin, devSignerArgs(append([]string{"--rewrap-keystore", "--keystore", keystore, "--kek", kekFile}, kms...)...)...).CombinedOutput() // #nosec G204 -- the test's own freshly built signer binary (CWE-78)
	if err != nil {
		t.Fatalf("--rewrap-keystore: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "(2 signer keys open under it)") || !strings.Contains(string(out), "kept at "+keystore+".pre-rewrap-") {
		t.Fatalf("--rewrap-keystore output = %s", out)
	}
	backups, err := filepath.Glob(keystore + ".pre-rewrap-*")
	if err != nil || len(backups) != 1 {
		t.Fatalf("rollback copies = %v, %v; want one", backups, err)
	}
	sealedKeys, err := filepath.Glob(filepath.Join(keystore, "*.key"))
	if err != nil || len(sealedKeys) != len(handles) {
		t.Fatalf("re-wrapped key files = %v, %v", sealedKeys, err)
	}
	for _, path := range sealedKeys {
		raw, err := os.ReadFile(path) // #nosec G304 -- the test's own temp key store (CWE-22)
		if err != nil || !bytes.Contains(raw, []byte("kmswrap:")) {
			t.Fatalf("%s does not carry the adapter's wrapped data key (%v)", filepath.Base(path), err)
		}
	}

	digest, err := crypto.Digest(crypto.SHA256, []byte("re-wrapped signer key store"))
	if err != nil {
		t.Fatal(err)
	}
	client, stop, err = start("b.sock", append([]string{"--keystore", keystore}, kms...)...)
	if err != nil {
		t.Fatalf("KMS-backed signer over the re-wrapped store: %v", err)
	}
	for _, handle := range handles {
		signer, err := client.SignerForHandle(ctx, handle)
		if err != nil {
			t.Fatalf("load %s from the re-wrapped store: %v", handle, err)
		}
		if !bytes.Equal(signer.Public().DER, publics[handle].DER) {
			t.Fatalf("%s is another key after the re-wrap", handle)
		}
		sig, err := signer.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256})
		if err != nil {
			t.Fatalf("sign with %s after the re-wrap: %v", handle, err)
		}
		if err := crypto.VerifyDigest(publics[handle], digest, sig, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
			t.Fatalf("the original public key of %s does not verify its signature: %v", handle, err)
		}
	}
	_ = client.Close()
	stop()

	if client, stop, err := start("c.sock", "--keystore", keystore, "--kek", kekFile); err == nil {
		_ = client.Close()
		stop()
		t.Fatal("the local KEK still starts the signer on the re-wrapped store")
	}
	client, stop, err = start("d.sock", "--keystore", backups[0], "--kek", kekFile)
	if err != nil {
		t.Fatalf("the rollback copy does not start under the local KEK: %v", err)
	}
	defer stop()
	defer func() { _ = client.Close() }()
	if signer, err := client.SignerForHandle(ctx, handles[0]); err != nil || !bytes.Equal(signer.Public().DER, publics[handles[0]].DER) {
		t.Fatalf("the rollback copy's %s = %v", handles[0], err)
	}
}
