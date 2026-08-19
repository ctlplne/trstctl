// SPDX-License-Identifier: MPL-2.0

package secretscan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// conformanceKeyPEM is the published connector conformance vector, copied byte
// for byte from internal/connector/conformance.go. It is a deterministic
// published test vector, not a live secret, and it is the ONE thing the
// repository's .gitleaks.toml still allowlists (by exact key body).
const conformanceKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2drNvkGQeqFUx3xE
zejpKQlXChZFd7J3qw/JXoL+x72hRANCAAThNg201ttWU9xWnLOcm66MA1dNuxpE
0vkPjUpV8HkZ0kQbfvY+C2fn0ynv7X49RvIdNtoonVFTSfq+Bbn8EILV
-----END PRIVATE KEY-----
`

// conformanceKeyBody is the base64 line .gitleaks.toml pins in its `regexes`
// allowlist. Deriving it from the PEM above keeps the two in lockstep.
func conformanceKeyBody() string { return strings.Split(conformanceKeyPEM, "\n")[1] }

// TestGitleaksConfigHasNoPathBasedTestSourceExemption is the SHAPE half of the
// SF.1 test-source coverage proof: it reads .gitleaks.toml as text and never
// invokes gitleaks. The BEHAVIOURAL half — a token planted in a *_test.go file
// is actually reported by a scan driven through the repository's own config —
// is TestServedGitleaksScanDetectsPlantedSecretInTestSource below. Keep both:
// the shape test always runs, the behavioural test needs the pinned binary.
//
// .gitleaks.toml used to carry a top-level `[allowlist] paths` list holding
// `.*_test\.go$` and `(^|/)testdata/`. A top-level allowlist `paths` entry
// short-circuits EVERY rule for a matching file, so that glob removed every
// `*_test.go` file and everything under `testdata/` — over a third of the
// tracked tree — from the entire ruleset: GitHub PATs, Slack bot tokens, AWS
// keys, JWTs, generic high-entropy assignments, all of it. The comment above it
// meanwhile claimed it suppressed "deterministic PEM private-key vectors only".
// No path exemption may come back: known fixture false positives are pinned one
// finding at a time in .gitleaksignore instead.
func TestGitleaksConfigHasNoPathBasedTestSourceExemption(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	cfg := readRepoFile(t, root, ".gitleaks.toml")

	for i, line := range strings.Split(cfg, "\n") {
		directive := strings.TrimSpace(line)
		if directive == "" || strings.HasPrefix(directive, "#") {
			continue
		}
		if strings.HasPrefix(directive, "paths") {
			t.Errorf(".gitleaks.toml:%d declares a path allowlist (%s); a path glob exempts a whole file from every rule, so pin individual findings in .gitleaksignore instead", i+1, directive)
		}
		if strings.HasPrefix(directive, "targetRules") {
			t.Errorf(".gitleaks.toml:%d declares targetRules (%s); the pinned gitleaks %s silently disables the entire allowlist block when it is present, which widens rather than narrows the suppression", i+1, directive, GitleaksPinnedVersion)
		}
	}

	if want := "'''" + conformanceKeyBody() + "'''"; !strings.Contains(cfg, want) {
		t.Errorf(".gitleaks.toml must keep the exact-key-body allowlist %s for the published connector conformance vector", want)
	}

	// The fixtures the path glob used to hide are pinned individually now, so
	// the rules that never fired on test sources are live. These five are a
	// representative sample of the classes involved: fake PAT / Slack / OAuth
	// corpus tokens, a JWT fixture, and a PEM fixture.
	ignore := readRepoFile(t, root, ".gitleaksignore")
	for _, fingerprint := range []string{
		"a04c8adabe271c5b5407a9a71bd75f1f4b1f814c:internal/aimodel/redactor_test.go:github-pat:152",
		"a04c8adabe271c5b5407a9a71bd75f1f4b1f814c:internal/aimodel/redactor_test.go:slack-bot-token:167",
		"8dd9416102e66c36c66a211227c250d5807bc337:internal/aimodel/redactor_test.go:github-oauth:97",
		"64b5c0f72bbba70657668631ab7a773726ace28e:internal/supportbundle/supportbundle_test.go:jwt:29",
		"caeb97d95f68356a19ed2420857d73a41d77457f:internal/crypto/jks/jks_test.go:private-key:13",
	} {
		if got := strings.Count(ignore, fingerprint); got != 1 {
			t.Errorf("test-source fixture exception %q occurs %d times, want exactly once", fingerprint, got)
		}
	}
}

// TestServedGitleaksScanDetectsPlantedSecretInTestSource is the BEHAVIOURAL SF.1
// acceptance for test sources, and the direct counterpart of
// TestServedGitleaksScanDetectsPlantedSecret (internal/server), which proves the
// same thing for production source. It plants secrets in a `*_test.go` file and
// runs the real pinned gitleaks binary over them through GitleaksRunner with the
// repository's own .gitleaks.toml in force — gitleaks resolves
// `(target path)/.gitleaks.toml` when no --config is passed (`gitleaks detect
// --help`, config precedence rule 4), so copying the repo config into the target
// directory exercises the shipped configuration end to end.
//
// The name is deliberately prefixed TestServedGitleaksScanDetectsPlantedSecret
// so the unanchored `-run` regex already pinned by
// TestParseGitleaksInstallerProvisioningPinned picks this up in the "Served
// Gitleaks scan smoke" step of .github/workflows/security.yml without editing
// either the workflow or that guard.
//
// Three assertions, and all three are load-bearing:
//   - a GitHub PAT in a `_test.go` file is reported — the class the old `paths`
//     glob hid while claiming to hide only PEM vectors;
//   - a PEM private key in a `_test.go` file is reported — so re-widening the
//     allowlist through `regexes`/`stopwords` for PEM bodies fails here too;
//   - the published conformance key in the same file is NOT reported — the
//     negative control proving the repository's .gitleaks.toml was actually
//     loaded. Without it, gitleaks silently falling back to its built-in default
//     config would satisfy the first two and prove nothing about this repo.
func TestServedGitleaksScanDetectsPlantedSecretInTestSource(t *testing.T) {
	bin, err := NewGitleaksRunner("").resolveBinary()
	if err != nil {
		// Fail closed where CI provisions the binary; skip only on a developer
		// machine that has not run tools/gitleaks/install.sh. This mirrors
		// requireGitleaksBinary in internal/server and is outside the
		// PCAS-scoped no-skip gate (scripts/pcas_no_skip_gate.sh).
		if strings.TrimSpace(os.Getenv("TRSTCTL_GITLEAKS_BIN")) != "" {
			t.Fatalf("TRSTCTL_GITLEAKS_BIN is set but no gitleaks binary resolved: %v", err)
		}
		t.Skip("SF.1 test-source acceptance requires the pinned Gitleaks binary; run tools/gitleaks/install.sh or set TRSTCTL_GITLEAKS_BIN")
	}

	target := t.TempDir()
	root := filepath.Clean(filepath.Join("..", ".."))
	if err := os.WriteFile(filepath.Join(target, ".gitleaks.toml"), []byte(readRepoFile(t, root, ".gitleaks.toml")), 0o600); err != nil {
		t.Fatalf("stage the repository gitleaks config: %v", err)
	}

	// Assembled at run time so this source file does not itself become a
	// finding, the same trick as sec07SlackBotToken in internal/server.
	plantedPAT := strings.Join([]string{"ghp", "16C7e42F292c6912E7710c838347Ae178B4a"}, "_")
	// A PEM whose body differs from the allowlisted conformance vector, so the
	// private-key rule fires and the `regexes` allowlist does not cover it.
	plantedKey := strings.Replace(conformanceKeyPEM, conformanceKeyBody(), "Q"+conformanceKeyBody()[1:], 1)
	if plantedKey == conformanceKeyPEM {
		t.Fatal("planted PEM must differ from the allowlisted conformance vector")
	}
	fixture := "package fixture\n\nconst plantedToken = \"" + plantedPAT + "\"\n\nconst plantedKey = `" + plantedKey + "`\n\nconst allowlistedConformanceKey = `" + conformanceKeyPEM + "`\n"
	const plantedName = "planted_leak_test.go"
	if err := os.WriteFile(filepath.Join(target, plantedName), []byte(fixture), 0o600); err != nil {
		t.Fatalf("write the planted test-source fixture: %v", err)
	}

	report, err := (&GitleaksRunner{Binary: bin, AllowedRoots: []string{target}}).ScanWithOptions(context.Background(), target, ScanOptions{})
	if err != nil {
		t.Fatalf("scan the planted test source: %v", err)
	}

	byRule := map[string]int{}
	var seen []string
	for _, f := range report.Findings {
		seen = append(seen, f.CredentialRef)
		if filepath.ToSlash(f.File) != plantedName {
			t.Errorf("finding outside the planted fixture %s: %s", plantedName, f.CredentialRef)
			continue
		}
		byRule[f.RuleID]++
	}
	for _, want := range []string{"github-pat", "private-key"} {
		if byRule[want] == 0 {
			t.Errorf("gitleaks reported no %q finding in %s under the repository's .gitleaks.toml; a secret planted in a test source is being suppressed. findings=%v", want, plantedName, seen)
		}
	}
	if byRule["private-key"] > 1 {
		t.Errorf("the allowlisted conformance vector in the same fixture was reported as well (%d private-key findings: %v); that means the repository .gitleaks.toml was NOT the config in force — gitleaks fell back to its built-in default — so the assertions above prove nothing about this repository's configuration", byRule["private-key"], seen)
	}
}
