// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/license"
)

func TestLicenseHelperSignsVerifiesAndInspectsOfflineLicense(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "vendor-ed25519.key")
	pubPath := filepath.Join(dir, "vendor-ed25519.pub")
	licPath := filepath.Join(dir, "license.json")

	var genOut bytes.Buffer
	if err := run([]string{"gen-key", "--private-key", privPath, "--public-key", pubPath}, &genOut, &bytes.Buffer{}); err != nil {
		t.Fatalf("gen-key: %v", err)
	}
	if !strings.Contains(genOut.String(), privPath) || !strings.Contains(genOut.String(), pubPath) {
		t.Fatalf("gen-key output did not name written key files: %q", genOut.String())
	}
	for _, path := range []string{privPath, pubPath} {
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			t.Fatalf("expected non-empty key file %s: info=%v err=%v", path, info, err)
		}
	}

	signArgs := []string{
		"sign",
		"--private-key", privPath,
		"--out", licPath,
		"--id", "lic-report-004",
		"--customer", "Example Corp",
		"--tier", string(license.TierProvider),
		"--production-deployment-id", "example-prod",
		"--features", string(license.FeatureGovernance) + ", " + string(license.FeatureProviderPlane),
		"--managed-customer-band", "25",
		"--issued-at", "2026-07-01T00:00:00Z",
		"--expires-at", "2027-07-01T00:00:00Z",
	}
	if err := run(signArgs, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("sign: %v", err)
	}

	var verifyOut bytes.Buffer
	if err := run([]string{"verify", "--license", licPath, "--public-key", pubPath}, &verifyOut, &bytes.Buffer{}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, want := range []string{"ok:", "lic-report-004", "Example Corp", string(license.TierProvider), "2027-07-01T00:00:00Z", "managed_customer_band=25", "managed_service", "resale"} {
		if !strings.Contains(verifyOut.String(), want) {
			t.Fatalf("verify output missing %q: %s", want, verifyOut.String())
		}
	}

	var inspectOut bytes.Buffer
	if err := run([]string{"inspect", "--license", licPath}, &inspectOut, &bytes.Buffer{}); err != nil {
		t.Fatalf("inspect: %v", err)
	}
	var claims license.Claims
	if err := json.Unmarshal(inspectOut.Bytes(), &claims); err != nil {
		t.Fatalf("inspect did not emit claims JSON: %v\n%s", err, inspectOut.String())
	}
	if claims.ID != "lic-report-004" || claims.Customer != "Example Corp" || claims.Tier != license.TierProvider {
		t.Fatalf("unexpected inspected claims: %+v", claims)
	}
	if claims.TenantBand != 25 {
		t.Fatalf("tenant band = %d, want 25", claims.TenantBand)
	}
	if got := parseFeatures(" governance, ,provider_plane "); len(got) != 2 || got[0] != license.FeatureGovernance || got[1] != license.FeatureProviderPlane {
		t.Fatalf("parseFeatures = %#v, want governance and provider_plane", got)
	}
}

func TestLicenseHelperBandFlagsAndTierValidation(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "vendor-ed25519.key")
	pubPath := filepath.Join(dir, "vendor-ed25519.pub")
	if err := run([]string{"gen-key", "--private-key", privPath, "--public-key", pubPath}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	base := []string{
		"sign", "--private-key", privPath, "--id", "lic-band", "--customer", "MSP",
		"--production-deployment-id", "msp-prod",
		"--issued-at", "2026-07-01T00:00:00Z", "--expires-at", "2027-07-01T00:00:00Z",
	}
	for name, extra := range map[string][]string{
		"enterprise customer band": {"--tier", "enterprise", "--managed-customer-band", "10"},
		"negative customer band":   {"--tier", "provider", "--managed-customer-band", "-1"},
		"both band flags":          {"--tier", "provider", "--managed-customer-band", "10", "--tenant-band", "10"},
		"unknown tier":             {"--tier", "platinum"},
	} {
		args := append(append([]string(nil), base...), extra...)
		if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Errorf("%s: sign succeeded, want error", name)
		}
	}

	legacy := append(append([]string(nil), base...), "--tier", "provider", "--tenant-band", "10")
	if err := run(legacy, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("deprecated --tenant-band must remain compatible: %v", err)
	}
}

func TestLicenseHelperRejectsIncompleteCommands(t *testing.T) {
	for _, tc := range [][]string{
		nil,
		{"unknown"},
		{"gen-key", "--private-key", "only-private"},
		{"sign", "--id", "missing-required-flags"},
		{"verify", "--license", "missing-public-key"},
		{"inspect"},
	} {
		if err := run(tc, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("run(%v) succeeded, want an error", tc)
		}
	}
}

func TestSignedLicenseOutputHasInstallerPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX license-file mode contract")
	}
	dir := t.TempDir()
	key, pub := filepath.Join(dir, "vendor.key"), filepath.Join(dir, "vendor.pub")
	if err := run([]string{"gen-key", "--private-key", key, "--public-key", pub}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, existing := range []bool{false, true} {
		name := "new"
		if existing {
			name = "existing-public-mode"
		}
		t.Run(name, func(t *testing.T) {
			out := filepath.Join(dir, name+".json")
			if existing {
				if err := os.WriteFile(out, []byte("superseded public license"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(out, 0o644); err != nil { // #nosec G302 -- regression fixture deliberately starts with an insecure mode to prove signing repairs it (CWE-276)
					t.Fatal(err)
				}
			}
			args := []string{"sign", "--private-key", key, "--out", out, "--id", "mode-fixture", "--customer", "QA", "--tier", "provider", "--production-deployment-id", "qa-mode", "--issued-at", "2026-07-01T00:00:00Z", "--expires-at", "2027-07-01T00:00:00Z"}
			if err := run(args, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
			st, err := os.Stat(out)
			if err != nil {
				t.Fatal(err)
			}
			if got := st.Mode().Perm(); got != 0o600 {
				t.Errorf("signed license mode = %04o, installer requires0600", got)
			}
			if err := run([]string{"verify", "--license", out, "--public-key", pub}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
