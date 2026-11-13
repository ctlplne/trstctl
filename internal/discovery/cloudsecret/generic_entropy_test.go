// SPDX-License-Identifier: BUSL-1.1

package cloudsecret

import (
	"encoding/json"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// a172l4Random is a random-looking token built at run time from a fixed
// seed, so no high-entropy literal sits in the repository.
func a172l4Random(alphabet string, n int, seed uint64) string {
	r := rand.New(rand.NewPCG(seed, seed^0xa172)) // #nosec G404 -- a seeded fixture generator: reproducible test data, not a secret (CWE-338)
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.IntN(len(alphabet))]
	}
	return string(b)
}

const (
	a172l4Base62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	a172l4Hex    = "0123456789abcdef"
)

// A172-L4: the generic high-entropy rule is a per-source opt-in. Off, a
// random-looking value no specific rule names is not reported; on, it is a
// masked, fingerprinted generic_high_entropy finding naming its field —
// never a second finding for a value a specific rule (or the service account
// rule) already named, and never for ordinary text.
func TestGenericHighEntropyRuleIsOptInA172L4(t *testing.T) {
	token := a172l4Random(a172l4Base62, 40, 1)
	gitlab := a172l1Token("gl"+"pat-", "A172l4shared", 26)
	value, err := json.Marshal(map[string]string{"api_secret": token, "gitlab": gitlab, "note": "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	inspect := func(generic bool) map[string]Credential {
		t.Helper()
		found, err := InspectSecret("hashicorp-vault", Secret{Name: "ci/app", Value: append([]byte(nil), value...), GenericHighEntropy: generic})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]Credential{}
		for _, f := range found {
			if f.Credential != nil {
				out[f.Credential.Field+"/"+f.Credential.Rule] = *f.Credential
			}
		}
		return out
	}
	off := inspect(false)
	if len(off) != 1 || off["gitlab/gitlab_token"].Fingerprint == "" {
		t.Fatalf("without the opt-in = %+v; want the GitLab token only", off)
	}
	on := inspect(true)
	generic, ok := on["api_secret/generic_high_entropy"]
	if len(on) != 2 || !ok || generic.Kind != "secret" || generic.Risk != genericHighEntropyRisk || generic.Masked != "…(40 chars)" ||
		generic.Fingerprint != credentialFingerprint([]byte(token)) {
		t.Fatalf("with the opt-in = %+v; want the GitLab token and one generic finding for api_secret", on)
	}
	if _, dup := on["gitlab/generic_high_entropy"]; dup {
		t.Fatal("a value a specific rule named was reported twice")
	}

	// A service account key file is one credential, not a field of random ids.
	sa, err := json.Marshal(map[string]string{"type": "service_account", "client_email": "deployer@a172l4.iam.gserviceaccount.com",
		"private_key_id": a172l4Random(a172l4Hex, 40, 2), "private_key": "-----BEGIN " + "PRIVATE KEY-----\nMIIEvA172l4\n-----END " + "PRIVATE KEY-----\n"})
	if err != nil {
		t.Fatal(err)
	}
	found, err := InspectSecret("gcp-secret-manager", Secret{Name: "deployer", Value: sa, GenericHighEntropy: true})
	if err != nil || len(found) != 1 || found[0].Credential.Rule != "gcp_service_account_key" {
		t.Fatalf("service account key with the opt-in = %+v err=%v", found, err)
	}

	for name, tc := range map[string]struct {
		value string
		want  bool
	}{
		"a base62 token":         {token, true},
		"a 40-hex token":         {a172l4Random(a172l4Hex, 40, 3), true},
		"a base64 key":           {a172l4Random(a172l4Base62+"+/", 44, 4), true},
		"too short":              {a172l4Random(a172l4Base62, 16, 5), false},
		"a short hex token":      {a172l4Random(a172l4Hex, 24, 6), false},
		"words":                  {"correct-horse-battery-staple", false},
		"a sentence":             {"this is not a secret at all, really", false},
		"a repeated password":    {"PasswordPassword12345", false},
		"a UUID":                 {"0b1e9a4c-7d3f-4e2a-9c51-6f0d8b2e7a13", false},
		"a URL":                  {"https://ci.example.com/api/v4/projects", false},
		"too long":               {a172l4Random(a172l4Base62, 600, 7), false},
		"surrounding whitespace": {"  " + token + "\n", true},
	} {
		if got := genericHighEntropy([]byte(tc.value)); got != tc.want {
			t.Fatalf("%s: generic = %v; want %v", name, got, tc.want)
		}
	}
}

// The opt-in needs content inspection: a source asking for the generic rule
// without reading values is refused before it is stored.
func TestGenericHighEntropyNeedsContentInspectionA172L4(t *testing.T) {
	if err := ValidateProviderOptions([]byte(`{"providers":[{"provider":"hashicorp-vault","inspect_content":true,"generic_high_entropy":true},
		{"provider":"azure-key-vault","generic_high_entropy":true}]}`)); !errors.Is(err, ErrGenericHighEntropyNeedsInspection) ||
		!strings.Contains(err.Error(), "provider 2") {
		t.Fatalf("generic without inspection = %v", err)
	}
	for _, ok := range []string{`{"providers":[{"provider":"hashicorp-vault","inspect_content":true,"generic_high_entropy":true}]}`,
		`{"providers":[{"provider":"hashicorp-vault"}]}`} {
		if err := ValidateProviderOptions([]byte(ok)); err != nil {
			t.Fatalf("%s refused: %v", ok, err)
		}
	}
}

// Every provider that inspects values passes the source's opt-in to the
// rules, so no provider silently ignores it.
func TestEveryInspectingProviderPassesTheGenericOptInA172L4(t *testing.T) {
	files, err := filepath.Glob("*/*.go")
	if err != nil {
		t.Fatal(err)
	}
	providers := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(file) // #nosec G304 -- repository source files under test (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		src := string(raw)
		calls := strings.Count(src, "cloudsecret.InspectSecret(")
		if calls == 0 {
			continue
		}
		providers++
		if passed := strings.Count(src, "GenericHighEntropy: e.cfg.GenericHighEntropy,"); passed != calls {
			t.Fatalf("%s inspects values %d times but passes the generic opt-in %d times", file, calls, passed)
		}
	}
	if providers < 11 {
		t.Fatalf("found %d inspecting providers; the guard is not looking at them", providers)
	}
}
