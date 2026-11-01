// SPDX-License-Identifier: BUSL-1.1

package cloudsecret

import (
	"strings"
	"testing"
)

// Credential-shaped fixtures are assembled at run time so the repository's
// own leak scanner never sees a token-shaped literal in this file.
func fixtureToken(prefix, body string, n int) string {
	return prefix + strings.Repeat(body, n/len(body)+1)[:n]
}

func credentialsByRule(found []Found) map[string]Credential {
	out := map[string]Credential{}
	for _, f := range found {
		if f.Kind == FindingKindAPIKey && f.Credential != nil {
			out[f.Credential.Rule] = *f.Credential
		}
	}
	return out
}

func TestInspectSecretFindsCredentialsWithoutKeepingThem(t *testing.T) {
	githubPAT := fixtureToken("gh"+"p_", "a172Xy9", 36)
	slack := fixtureToken("xo"+"xb-", "17221-", 40)
	awsID := "AK" + "IA" + "A172TESTKEY00001"
	awsSecret := fixtureToken("", "A172+secret/Key", 40)
	pemKey := "-----BEGIN " + "EC PRIVATE KEY-----\nMHcCAQEEIA172fixturefixturefixture\n-----END " + "EC PRIVATE KEY-----"
	value := []byte(`{"github":"` + githubPAT + `","slack_bot":"` + slack + `","aws_access_key_id":"` + awsID +
		`","aws_secret_access_key":"` + awsSecret + `","tls_key":"` + strings.ReplaceAll(pemKey, "\n", `\n`) + `","port":8443}`)
	found, err := InspectSecret("aws-secrets-manager", Secret{Name: "app/prod", ResourceID: "arn:a172", Location: "us-east-1",
		Provenance: "aws-sm://us-east-1/app/prod", Value: value, Metadata: map[string]string{"secret_name": "app/prod"}})
	if err != nil {
		t.Fatal(err)
	}
	creds := credentialsByRule(found)
	want := map[string]struct{ kind, field, masked string }{
		"github_personal_access_token": {"personal_access_token", "github", "ghp_…(40 chars)"},
		"slack_token":                  {"api_token", "slack_bot", "xoxb-…(45 chars)"},
		"aws_access_key_id":            {"api_key", "aws_access_key_id", "AKIA…(20 chars)"},
		"aws_secret_access_key":        {"api_key", "aws_secret_access_key", "…(40 chars)"},
		"private_key_pem":              {"private_key", "tls_key", "-----BEGIN EC PRIVATE KEY-----"},
	}
	if len(creds) != len(want) {
		t.Fatalf("credentials = %+v", creds)
	}
	for rule, w := range want {
		c, ok := creds[rule]
		if !ok || c.Kind != w.kind || c.Field != w.field || c.Masked != w.masked || len(c.Fingerprint) != 64 {
			t.Fatalf("%s = %+v, want %+v", rule, c, w)
		}
	}
	for _, f := range found {
		for _, raw := range []string{githubPAT, slack, awsSecret, "MHcCAQEEIA172"} {
			if strings.Contains(f.Credential.Masked, raw) || strings.Contains(f.Credential.Fingerprint, raw) {
				t.Fatalf("finding carries the value: %+v", f.Credential)
			}
			for _, v := range f.Metadata {
				if strings.Contains(v, raw) {
					t.Fatalf("metadata carries the value: %+v", f.Metadata)
				}
			}
		}
	}
}

func TestCredentialFingerprintIsEqualAcrossStoresAndFields(t *testing.T) {
	token := fixtureToken("gl"+"pat-", "A172gitlab", 26)
	a, err := InspectSecret("hashicorp-vault", Secret{Name: "ci/gitlab", Fields: []SecretField{{Name: "token", Value: []byte(token)}}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := InspectSecret("azure-key-vault", Secret{Name: "gitlab-token", Value: []byte("GITLAB_TOKEN=" + token + "\n")})
	if err != nil {
		t.Fatal(err)
	}
	ca, cb := credentialsByRule(a)["gitlab_token"], credentialsByRule(b)["gitlab_token"]
	if ca.Fingerprint == "" || ca.Fingerprint != cb.Fingerprint || ca.Field != "token" || cb.Field != "" {
		t.Fatalf("vault %+v, azure %+v", ca, cb)
	}
}

func TestServiceAccountKeyNamesItsPrincipalOnce(t *testing.T) {
	pemKey := "-----BEGIN " + "PRIVATE KEY-----\nMIIEvA172serviceaccountfixture\n-----END " + "PRIVATE KEY-----\n"
	value := []byte(`{"type":"service_account","project_id":"a172","private_key_id":"k1","private_key":"` +
		strings.ReplaceAll(pemKey, "\n", `\n`) + `","client_email":"deployer@a172.iam.gserviceaccount.com"}`)
	found, err := InspectSecret("gcp-secret-manager", Secret{Name: "deployer-key", Value: value})
	if err != nil {
		t.Fatal(err)
	}
	creds := credentialsByRule(found)
	sa, ok := creds["gcp_service_account_key"]
	if !ok || len(creds) != 1 || sa.Principal != "deployer@a172.iam.gserviceaccount.com" || sa.Field != "private_key" ||
		sa.Masked != "service account deployer@a172.iam.gserviceaccount.com" {
		t.Fatalf("credentials = %+v", creds)
	}
}

func TestInspectSecretIgnoresPlainValuesAndBoundsFloods(t *testing.T) {
	plain, err := InspectSecret("aws-secrets-manager", Secret{Name: "db", Value: []byte(`{"username":"app","password":"correct horse battery staple"}`)})
	if err != nil || len(plain) != 0 {
		t.Fatalf("plain value = %+v, %v", plain, err)
	}
	var flood strings.Builder
	for i := 0; i < maxCredentialsPerSecret+10; i++ {
		flood.WriteString(fixtureToken("np"+"m_", "A172"+string(rune('a'+i%26))+string(rune('a'+i/26)), 36))
		flood.WriteByte('\n')
	}
	found, err := InspectSecret("aws-secrets-manager", Secret{Name: "flood", Value: []byte(flood.String())})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != maxCredentialsPerSecret || !found[0].Credential.Truncated {
		t.Fatalf("flood = %d findings (truncated %v)", len(found), found[0].Credential.Truncated)
	}
}
