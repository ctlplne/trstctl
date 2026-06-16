package sshkeys_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"

	"trstctl.com/trstctl/internal/crypto/sshkeys"
)

// seedAuthorizedLine builds one real "ssh-ed25519 AAAA... comment" line so the
// fuzz corpus reaches the success path. This test is inside the AN-3 boundary
// (internal/crypto/sshkeys), so it may use the SSH crypto library directly.
func seedAuthorizedLine(tb testing.TB) []byte {
	tb.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		tb.Fatal(err)
	}
	return ssh.MarshalAuthorizedKey(sshPub) // "ssh-ed25519 AAAA...\n"
}

// FuzzParseAuthorizedKeys: parsing an authorized_keys file must never panic and
// must terminate (the fuzz timeout catches a non-advancing loop) on arbitrary
// bytes. CLAUDE.md §6.
func FuzzParseAuthorizedKeys(f *testing.F) {
	f.Add(seedAuthorizedLine(f))
	f.Add([]byte(""))
	f.Add([]byte("garbage line\nanother\n"))
	f.Add([]byte("ssh-ed25519 AAAA notvalidbase64 comment"))
	f.Add([]byte(`command="x",from="*" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 c`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = sshkeys.ParseAuthorizedKeys(data)
	})
}

// FuzzParseKnownHosts: parsing a known_hosts file must never panic and must
// terminate on arbitrary bytes.
func FuzzParseKnownHosts(f *testing.F) {
	f.Add(append([]byte("example.com "), seedAuthorizedLine(f)...))
	f.Add([]byte(""))
	f.Add([]byte("|1|garbage\n"))
	f.Add([]byte("example.com ssh-ed25519 notbase64\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = sshkeys.ParseKnownHosts(data)
	})
}

// FuzzParsePublicKey: parsing a single .pub / host-key file must never panic on
// arbitrary bytes.
func FuzzParsePublicKey(f *testing.F) {
	f.Add(seedAuthorizedLine(f))
	f.Add([]byte(""))
	f.Add([]byte("ssh-rsa"))
	f.Add([]byte("ssh-ed25519 @@@@ comment"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = sshkeys.ParsePublicKey(data)
	})
}
