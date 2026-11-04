// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bytes"
	"strings"
	"testing"
)

// record feeds writes through a masker and returns everything it released.
func record(m *masker, writes ...string) string {
	var out bytes.Buffer
	for _, w := range writes {
		out.Write(m.Write([]byte(w)))
	}
	out.Write(m.Flush())
	return out.String()
}

func TestMaskerMasksSecretsSplitAcrossWritesA255(t *testing.T) {
	password := "s3ssion-Pa55word-0123456789"
	key := "AKIA" + "IOSFODNN7EXAMPLE"
	jwt := "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLWJ5dGVz"
	// Split so the repository's own secret scan does not read the fixture as
	// a key.
	pemKey := "-----BEGIN OPENSSH PRIVATE" + " KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE" + " KEY-----"
	for name, tc := range map[string]struct {
		writes []string
		want   string
	}{
		"credential split": {[]string{"login ok, pass=" + password[:9], password[9:] + " done\n"},
			"login ok, pass=[masked:session-credential] done\n"},
		"aws key split": {[]string{"export AWS_ACCESS_KEY_ID=" + key[:6], key[6:] + "\n"},
			"export AWS_ACCESS_KEY_ID=[masked:aws-access-key-id]\n"},
		"jwt in three writes": {[]string{"Bearer " + jwt[:10], jwt[10:40], jwt[40:] + "\n"}, "Bearer [masked:jwt]\n"},
		"private key block": {[]string{"$ cat id\n" + pemKey[:30], pemKey[30:70], pemKey[70:] + "\n$ "},
			"$ cat id\n[masked:private-key]\n$ "},
		"token at the end of the stream": {[]string{"token: ghp_" + strings.Repeat("a", 36)}, "token: [masked:github-token]"},
	} {
		t.Run(name, func(t *testing.T) {
			m := newMasker([]byte(password))
			defer m.Close()
			if got := record(m, tc.writes...); got != tc.want {
				t.Fatalf("recorded %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMaskerReleasesOrdinaryOutputAtOnceA255(t *testing.T) {
	m := newMasker([]byte("s3ssion-Pa55word"))
	defer m.Close()
	for _, line := range []string{"total 8\n", "drwxr-xr-x  2 alice alice 4096 .\n", "$ "} {
		if got := string(m.Write([]byte(line))); got != line {
			t.Fatalf("ordinary output %q was held back (released %q)", line, got)
		}
	}
	// Only what may still become a secret waits: the start of the
	// credential at the end of a write, or a token still running.
	if got := string(m.Write([]byte("echo s3ss"))); got != "echo " {
		t.Fatalf("released %q, want the credential's start held", got)
	}
	if got := string(m.Write([]byte("ion is fine\n"))); got != "s3ssion is fine\n" {
		t.Fatalf("released %q once it was not the credential", got)
	}
}

func TestMaskerBoundsAnUnterminatedPrivateKeyA255(t *testing.T) {
	m := newMasker()
	defer m.Close()
	got := string(m.Write([]byte("-----BEGIN RSA PRIVATE KEY-----\n" + strings.Repeat("A", maskKeyHold+10))))
	if got != "[masked:private-key]" || strings.Contains(string(m.Flush()), "AAAA") {
		t.Fatalf("an unterminated key released %q", got)
	}
}
