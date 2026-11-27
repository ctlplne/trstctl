// SPDX-License-Identifier: BUSL-1.1

package crypto

import (
	"bytes"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestNormalizeDeploymentPrivateKeyPEMRejectsHiddenInput(t *testing.T) {
	key, _, err := GenerateUploadableRSAKeypair(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(key)
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"prefix", append([]byte("extra data\n"), key...)},
		{"suffix", append(append([]byte(nil), key...), []byte("extra data\n")...)},
		{"second block", append(append([]byte(nil), key...), key...)},
		{"not a key", malformedDeploymentKeyPEM()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			protected, _, err := NormalizeDeploymentPrivateKeyPEM(tc.raw)
			if protected != nil {
				protected.Destroy()
			}
			if err == nil {
				t.Fatal("untrusted private-key envelope was accepted")
			}
		})
	}
	protected, info, err := NormalizeDeploymentPrivateKeyPEM(append([]byte(" \n"), key...))
	if err != nil {
		t.Fatal(err)
	}
	defer protected.Destroy()
	if info.FingerprintSHA256 == "" || !bytes.Equal(protected.Bytes(), key) {
		t.Fatal("valid key was not canonicalized into protected memory")
	}
}

func FuzzNormalizeDeploymentPrivateKeyPEM(f *testing.F) {
	f.Add([]byte("not a key"))
	f.Add(malformedDeploymentKeyPEM())
	key, _, err := GenerateUploadableRSAKeypair(time.Hour)
	if err != nil {
		f.Fatal(err)
		return
	}
	f.Add(key)
	secret.Wipe(key)
	f.Fuzz(func(t *testing.T, raw []byte) {
		protected, info, err := NormalizeDeploymentPrivateKeyPEM(raw)
		if err != nil {
			return
		}
		defer protected.Destroy()
		if info.FingerprintSHA256 == "" {
			t.Fatal("accepted private key without a public identity")
		}
		again, second, err := NormalizeDeploymentPrivateKeyPEM(protected.Bytes())
		if err != nil {
			t.Fatalf("canonical private key does not parse: %v", err)
		}
		defer again.Destroy()
		if !bytes.Equal(protected.Bytes(), again.Bytes()) || info.FingerprintSHA256 != second.FingerprintSHA256 {
			t.Fatal("private key normalization changed bytes or public identity")
		}
	})
}

func malformedDeploymentKeyPEM() []byte {
	label := "PRIVATE KEY"
	return []byte("-----BEGIN " + label + "-----\nZmFrZQ==\n-----END " + label + "-----\n")
}
