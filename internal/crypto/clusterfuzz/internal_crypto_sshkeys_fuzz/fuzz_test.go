// SPDX-License-Identifier: MPL-2.0

package clusterfuzz

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ssh"

	"trstctl.com/trstctl/internal/crypto/sshkeys"
)

// "ssh-ed25519 AAAA...\n"

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

func FuzzParseKnownHosts(f *testing.F) {
	f.Add(append([]byte("example.com "), seedAuthorizedLine(f)...))
	f.Add([]byte(""))
	f.Add([]byte("|1|garbage\n"))
	f.Add([]byte("example.com ssh-ed25519 notbase64\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = sshkeys.ParseKnownHosts(data)
	})
}

func FuzzParsePublicKey(f *testing.F) {
	f.Add(seedAuthorizedLine(f))
	f.Add([]byte(""))
	f.Add([]byte("ssh-rsa"))
	f.Add([]byte("ssh-ed25519 @@@@ comment"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = sshkeys.ParsePublicKey(data)
	})
}

func seedAuthorizedLine(f *testing.F) []byte {
	f.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		f.Fatal(err)
	}
	return ssh.MarshalAuthorizedKey(sshPub)
}
