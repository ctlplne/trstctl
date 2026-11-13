// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/secretscan"
)

// a172l1Fingerprint is the fingerprint a stored copy of value carries.
func a172l1Fingerprint(t *testing.T, value string) string {
	t.Helper()
	found := cloudsecret.CredentialsStartingIn([]byte(value), 0, len(value))
	if len(found) != 1 {
		t.Fatalf("fixture %d credentials in one value", len(found))
	}
	return found[0].Fingerprint
}

// A172-L1: the credential a leaked secret's line holds is the one the
// scanner's match covers, under either column convention gitleaks reports;
// without columns, the only credential on the line; never a guess between
// several, a credential beside a match it does not cover, or a line the
// scanned tree does not hold.
func TestLeakedCredentialIsTheOneTheScannerPointsAtA172L1(t *testing.T) {
	awsID := "AK" + "IA" + "A172L1LEAKEDKEY0"
	github := "gh" + "p_" + strings.Repeat("A172l1pat", 4)[:36]
	gitlab := "gl" + "pat-" + strings.Repeat("A172l1leak", 3)[:26]
	pem := "-----BEGIN " + "PRIVATE KEY-----\nMIIEvA172l1leakedkey\n-----END " + "PRIVATE KEY-----"
	lines := []string{
		"both: " + awsID + " " + github,
		`GITLAB_TOKEN = "` + gitlab + `"`,
		"password=correct-horse-battery-staple " + awsID,
		pem,
		"done",
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "app.env"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	col := func(line int, value string) (int, int) {
		i := strings.Index(lines[line-1], value)
		if line == 1 {
			return i + 1, i + len(value) // gitleaks on a file's first line
		}
		return i + 2, i + len(value) + 1 // gitleaks on a later line
	}
	at := func(line int, value string) secretscan.Finding {
		c, e := col(line, value)
		return secretscan.Finding{File: "app.env", Line: line, Column: c, EndLine: line, EndColumn: e}
	}
	want := map[string]string{"aws": a172l1Fingerprint(t, awsID), "github": a172l1Fingerprint(t, github), "gitlab": a172l1Fingerprint(t, gitlab),
		"pem": a172l1Fingerprint(t, pem)}
	for name, tc := range map[string]struct {
		f    secretscan.Finding
		want string
	}{
		"the PAT beside a key":           {at(1, github), want["github"]},
		"the key beside a PAT":           {at(1, awsID), want["aws"]},
		"a token on a later line":        {at(2, gitlab), want["gitlab"]},
		"no columns, one credential":     {secretscan.Finding{File: "app.env", Line: 2}, want["gitlab"]},
		"no columns, two credentials":    {secretscan.Finding{File: "app.env", Line: 1}, ""},
		"a match that covers no shape":   {at(3, "correct-horse-battery-staple"), ""},
		"a PEM block over several lines": {secretscan.Finding{File: "app.env", Line: 4, Column: 2, EndLine: 6, EndColumn: 30}, want["pem"]},
		"a line the tree does not hold":  {secretscan.Finding{File: "app.env", Line: 40, Column: 2, EndLine: 40, EndColumn: 9}, ""},
		"a file outside the tree":        {secretscan.Finding{File: "../app.env", Line: 2}, ""},
	} {
		got, ok := leakedCredential(root, tc.f)
		if (tc.want == "") == ok || got.Fingerprint != tc.want {
			t.Fatalf("%s: credential %q ok=%v; want %q", name, got.Fingerprint, ok, tc.want)
		}
	}
	if got, _ := leakedCredential(root, at(1, github)); got.Rule != "github_personal_access_token" || strings.Contains(got.Masked, github[4:]) {
		t.Fatalf("PAT credential = %+v", got)
	}
}
