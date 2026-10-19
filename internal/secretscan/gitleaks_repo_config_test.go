// SPDX-License-Identifier: BUSL-1.1

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
// published test vector, not a live secret. The repository's .gitleaks.toml
// allows it only in five named files under the private-key rule.
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
// invokes gitleaks. The BEHAVIORAL tests below plant credentials in both test
// source and a generated chunk using the repository's own config. Keep both:
// this shape test always runs, while the behavioral tests need the pinned binary.
//
// .gitleaks.toml used to carry a top-level `[allowlist] paths` list holding
// `.*_test\.go$` and `(^|/)testdata/`. A top-level allowlist `paths` entry
// short-circuits EVERY rule for a matching file, so that glob removed every
// `*_test.go` file and everything under `testdata/` — over a third of the
// tracked tree — from the entire ruleset: GitHub PATs, Slack bot tokens, AWS
// keys, JWTs, generic high-entropy assignments, all of it. The comment above it
// meanwhile claimed it suppressed "deterministic PEM private-key vectors only".
// No whole-file path exemption may come back. The one rule-specific path below
// also requires the exact static translation-lookup match, so a real key in the
// same generated chunk still fails.
func TestGitleaksConfigHasNoPathBasedTestSourceExemption(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	cfg := readRepoFile(t, root, ".gitleaks.toml")

	section := ""
	var scopedPaths int
	for i, line := range strings.Split(cfg, "\n") {
		directive := strings.TrimSpace(line)
		if directive == "" || strings.HasPrefix(directive, "#") {
			continue
		}
		if strings.HasPrefix(directive, "[") {
			section = directive
			continue
		}
		if strings.HasPrefix(directive, "paths") {
			const exactGeneratedPath = "paths = ['''(^|/)internal/webui/dist/assets/Journeys-[A-Za-z0-9_-]+\\.js$''']"
			const exactFixturePaths = "paths = ['''(^|/)internal/(connector/conformance\\.go|connector/iis/iis_test\\.go|projections/iis_connector_test\\.go|server/run_connectors_test\\.go|secretscan/gitleaks_repo_config_test\\.go)$''']"
			if section != "[[rules.allowlists]]" || (directive != exactGeneratedPath && directive != exactFixturePaths) {
				t.Errorf(".gitleaks.toml:%d declares an unbounded path allowance in %s: %s", i+1, section, directive)
			}
			scopedPaths++
		}
		if strings.HasPrefix(directive, "targetRules") {
			t.Errorf(".gitleaks.toml:%d declares targetRules (%s); the pinned gitleaks %s silently disables the entire allowlist block when it is present, which widens rather than narrows the suppression", i+1, directive, GitleaksPinnedVersion)
		}
	}
	if scopedPaths != 2 || strings.Count(cfg, "id = \"generic-api-key\"") != 1 || strings.Count(cfg, "id = \"private-key\"") != 1 ||
		!strings.Contains(cfg, "condition = \"AND\"") ||
		!strings.Contains(cfg, "regexTarget = \"match\"") ||
		!strings.Contains(cfg, "regexes = ['''^bodyKey:[\"`]journeys\\.[A-Za-z0-9_.-]+[\"`]$''']") {
		t.Error("generated Journey allowance must remain rule-specific and require the exact path AND static bodyKey match")
	}

	if want := "'''" + conformanceKeyBody() + "'''"; !strings.Contains(cfg, want) {
		t.Errorf(".gitleaks.toml must keep the exact-key-body allowance %s for the published connector conformance vector", want)
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

// TestGitleaksHistoricalGeneratedIdentifierPinsAreExact guards the narrow
// repository-history exceptions discovered by the G114 full-history scan. Each
// match was inspected at its introducing commit: they are OpenAPI operation IDs,
// an i18n review sentence, or compiled journey translation lookup keys—not
// credentials. Exact commit/path/rule/line fingerprints keep every new match red.
func TestGitleaksHistoricalGeneratedIdentifierPinsAreExact(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	ignore := readRepoFile(t, root, ".gitleaksignore")
	for _, fingerprint := range []string{
		"8f2698b4c27b1d546835acc9c04361fcecedb613:internal/featureparity/feature-map-backlog.json:generic-api-key:6605",
		"8f2698b4c27b1d546835acc9c04361fcecedb613:web/src/lib/feature-contracts.gen.ts:generic-api-key:2311",
		"b53d74a08d7a875e7ec5b6b04f1ec030e1eddc5e:internal/featureparity/feature-map-backlog.json:generic-api-key:6325",
		"b53d74a08d7a875e7ec5b6b04f1ec030e1eddc5e:internal/featureparity/feature-map-backlog.json:generic-api-key:6360",
		"b53d74a08d7a875e7ec5b6b04f1ec030e1eddc5e:web/src/lib/feature-contracts.gen.ts:generic-api-key:2196",
		"b53d74a08d7a875e7ec5b6b04f1ec030e1eddc5e:web/src/lib/feature-contracts.gen.ts:generic-api-key:2231",
		"eb40c95d82f3e04ea78cfbaecdb3a48c0bc67378:internal/featureparity/feature-map-backlog.json:generic-api-key:6050",
		"eb40c95d82f3e04ea78cfbaecdb3a48c0bc67378:web/src/lib/feature-contracts.gen.ts:generic-api-key:2114",
		"42512cbd29fac11c5623b7340bb49d4f849ecca7:web/src/__tests__/i18n.test.tsx:generic-api-key:1212",
		"71515d76e72ab82a766f29d84a67d22716b07fbc:internal/webui/dist/assets/Journeys-Y8YkXAnJ.js:generic-api-key:8",
		"71515d76e72ab82a766f29d84a67d22716b07fbc:internal/webui/dist/assets/Journeys-Y8YkXAnJ.js:generic-api-key:13",
	} {
		if got := strings.Count(ignore, fingerprint); got != 1 {
			t.Errorf("inspected historical false-positive fingerprint %q occurs %d times, want exactly once", fingerprint, got)
		}
	}
}

// TestServedGitleaksScanDetectsPlantedSecretInTestSource is the BEHAVIORAL SF.1
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
//   - the published conformance key in an unrelated test file IS reported;
//     only the five named source/fixture files may hold that exact vector;
//   - the same vector in the named conformance path is suppressed, proving
//     the repository's file-and-rule scoped config was actually loaded.
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
	conformancePath := filepath.Join(target, "internal", "connector", "conformance.go")
	if err := os.MkdirAll(filepath.Dir(conformancePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conformancePath, []byte("package connector\nconst publishedVector = `"+conformanceKeyPEM+"`\n"), 0o600); err != nil {
		t.Fatal(err)
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
	if byRule["private-key"] != 2 {
		t.Errorf("private-key findings in unlisted test source = %d, want 2; an exact published vector must not be allowed in an arbitrary file. findings=%v", byRule["private-key"], seen)
	}
}

func TestServedGitleaksGeneratedJourneyAllowanceKeepsSecretsVisible(t *testing.T) {
	bin, err := NewGitleaksRunner("").resolveBinary()
	if err != nil {
		if strings.TrimSpace(os.Getenv("TRSTCTL_GITLEAKS_BIN")) != "" {
			t.Fatalf("TRSTCTL_GITLEAKS_BIN is set but no gitleaks binary resolved: %v", err)
		}
		t.Skip("generated-bundle allowance test requires the pinned Gitleaks binary")
	}

	target := t.TempDir()
	root := filepath.Clean(filepath.Join("..", ".."))
	if err := os.WriteFile(filepath.Join(target, ".gitleaks.toml"), []byte(readRepoFile(t, root, ".gitleaks.toml")), 0o600); err != nil {
		t.Fatal(err)
	}
	generatedDir := filepath.Join(target, "internal", "webui", "dist", "assets")
	if err := os.MkdirAll(generatedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Build both scanner bait values at run time so this test source does not
	// itself become a repository-history finding. The first is only a static
	// translation lookup; the second has the shape of a generic API key.
	bodyKey := "body" + "Key:" + `"` + strings.Join([]string{"journeys", "qa", "cancel", "CA8a72qZ", "body"}, ".") + `"`
	genericKey := strings.Join([]string{"q9BZ3sNfH72WmRa4", "T8VkP65cYxU1dLoE"}, "")
	generated := "const row={" + bodyKey + "};\nconst api_key=\"" + genericKey + "\";\n"
	generatedName := "Journeys-qa123456.js"
	if err := os.WriteFile(filepath.Join(generatedDir, generatedName), []byte(generated), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "manual.js"), []byte("const row={"+bodyKey+"};\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := (&GitleaksRunner{Binary: bin, AllowedRoots: []string{target}}).ScanWithOptions(context.Background(), target, ScanOptions{})
	if err != nil {
		t.Fatalf("scan generated and ordinary files: %v", err)
	}
	var generatedLookup, generatedKey, ordinaryLookup int
	for _, finding := range report.Findings {
		path := filepath.ToSlash(finding.File)
		switch {
		case strings.HasSuffix(path, "/"+generatedName) && finding.RuleID == "generic-api-key" && finding.Line == 1:
			generatedLookup++
		case strings.HasSuffix(path, "/"+generatedName) && finding.RuleID == "generic-api-key" && finding.Line == 2:
			generatedKey++
		case path == "manual.js" && finding.RuleID == "generic-api-key" && finding.Line == 1:
			ordinaryLookup++
		}
	}
	if generatedLookup != 0 || generatedKey != 1 || ordinaryLookup != 1 {
		t.Errorf("generated lookup=%d, planted key in same bundle=%d, ordinary-file lookup=%d; want 0,1,1", generatedLookup, generatedKey, ordinaryLookup)
	}
}
