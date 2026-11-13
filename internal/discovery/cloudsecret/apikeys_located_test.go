// SPDX-License-Identifier: BUSL-1.1

package cloudsecret

import (
	"strings"
	"testing"
)

// a172l1Token assembles a credential-shaped fixture at run time so the
// repository's own leak scanner never sees a token-shaped literal.
func a172l1Token(prefix, body string, n int) string {
	return prefix + strings.Repeat(body, n/len(body)+1)[:n]
}

// A172-L1: a credential matched on a leaked secret's line is fingerprinted
// exactly as the stored copy of the same credential is, so the two line up;
// only a match that starts in the range is returned, and a PEM block that
// starts there is matched whole.
func TestCredentialsStartingInFingerprintAsAStoredCopyA172L1(t *testing.T) {
	gitlab := a172l1Token("gl"+"pat-", "A172l1shared", 26)
	stored, err := InspectSecret("hashicorp-vault", Secret{Name: "ci/gitlab", Value: []byte("GITLAB_TOKEN=" + gitlab + "\n")})
	if err != nil || len(stored) != 1 || stored[0].Credential == nil {
		t.Fatalf("stored = %+v err=%v", stored, err)
	}
	line := []byte(`export GITLAB_TOKEN="` + gitlab + `" # ci`)
	found := CredentialsStartingIn(line, 0, len(line))
	if len(found) != 1 || found[0].Fingerprint != stored[0].Credential.Fingerprint || found[0].Rule != "gitlab_token" ||
		string(line[found[0].Start:found[0].End]) != gitlab {
		t.Fatalf("on the line = %+v; want the stored fingerprint %s", found, stored[0].Credential.Fingerprint)
	}
	if got := CredentialsStartingIn(line, 0, found[0].Start); len(got) != 0 {
		t.Fatalf("a credential starting after the range was returned: %+v", got)
	}

	github := a172l1Token("gh"+"p_", "A172l1pat", 36)
	two := []byte("both: " + "AK" + "IA" + "A172L1LEAKEDKEY0" + " " + github)
	if got := CredentialsStartingIn(two, 0, len(two)); len(got) != 2 || got[0].End >= got[1].Start && got[1].End >= got[0].Start {
		t.Fatalf("two credentials on one line = %+v; want two apart", got)
	}

	pem := "-----BEGIN " + "PRIVATE KEY-----\nMIIEvA172l1leakedkey\n-----END " + "PRIVATE KEY-----"
	storedPEM, err := InspectSecret("hashicorp-vault", Secret{Name: "tls/key", Value: []byte(pem)})
	if err != nil || len(storedPEM) != 1 {
		t.Fatalf("stored PEM = %+v err=%v", storedPEM, err)
	}
	text := []byte(pem + "\nnext")
	firstLine := strings.IndexByte(pem, '\n')
	if got := CredentialsStartingIn(text, 0, firstLine); len(got) != 1 || got[0].Rule != "private_key_pem" ||
		got[0].Fingerprint != storedPEM[0].Credential.Fingerprint {
		t.Fatalf("PEM starting on the line = %+v", got)
	}
	if got := CredentialsStartingIn([]byte("password=correct-horse-battery"), 0, 30); len(got) != 0 {
		t.Fatalf("a plain value matched %+v", got)
	}
}
