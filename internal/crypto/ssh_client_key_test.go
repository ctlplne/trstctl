// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestGenerateSSHClientKeyA239L11: an SSH lease's key pair is an Ed25519
// OpenSSH private key and its matching authorized_keys public key, which a
// certificate this boundary signs certifies; the public half is recovered from
// the prepared private key alone.
func TestGenerateSSHClientKeyA239L11(t *testing.T) {
	private, public, err := GenerateSSHClientKey("trstctl-lease-1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(private, []byte("-----BEGIN OPENSSH PRIVATE KEY-----")) || !strings.HasPrefix(string(public), "ssh-ed25519 ") {
		t.Fatalf("key pair forms: %q / %q", private[:40], public)
	}
	signer, err := ssh.ParsePrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if got := ssh.MarshalAuthorizedKey(signer.PublicKey()); !bytes.Equal(got, public) {
		t.Fatalf("the public key %q does not match the private key's %q", public, got)
	}
	again, err := SSHAuthorizedKeyOfPrivateKey(private)
	if err != nil || !bytes.Equal(again, public) {
		t.Fatalf("public key from the prepared private key = %q, %v", again, err)
	}
	other, _, err := GenerateSSHClientKey("trstctl-lease-2")
	if err != nil || bytes.Equal(other, private) {
		t.Fatal("two leases got the same key")
	}
	if _, err := SSHAuthorizedKeyOfPrivateKey([]byte("not a key")); err == nil {
		t.Fatal("a malformed private key was accepted")
	}
}
