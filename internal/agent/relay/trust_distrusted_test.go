// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func distrustFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "keyposture", "testdata", name)) // #nosec G304 -- a fixed test fixture directory, named by the test itself (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func anchorFingerprintOf(t *testing.T, pemBytes []byte) string {
	t.Helper()
	info, err := certinfo.Inspect(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	return info.SHA256Fingerprint
}

func writeAnchor(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// eMudhra, Part 4: a host trust store holding emSign ECC Root CA - G3 in its
// own file loses exactly that file; everything else the removal could touch
// is left alone and the report says why.
func TestDistrustedRootRemovalRemovesOnlyASingleListedAnchor(t *testing.T) {
	dir := t.TempDir()
	profile := connector.LocalOpsConfig{AllowedRoots: []string{dir}}
	emsign := distrustFixture(t, "emsign-ecc-root-ca-g3.pem")
	ordinary := distrustFixture(t, "ecdsa-p256-ordinary.pem")
	emsignFP := anchorFingerprintOf(t, emsign)
	intent := func(path, fingerprint string) TrustDistributionIntent {
		return TrustDistributionIntent{Operation: TrustRemoveDistrusted, FindingID: "finding-1", AnchorPath: path, AnchorFingerprint: fingerprint}
	}
	run := func(in TrustDistributionIntent) DistrustRemovalReport {
		t.Helper()
		report, err := ExecuteDistrustedRootRemoval(profile, in)
		if err != nil {
			t.Fatalf("%s: %v", in.AnchorPath, err)
		}
		if err := ValidateDistrustRemovalReport(in, report, report.Digest()); err != nil {
			t.Fatalf("%s: report does not validate: %v", in.AnchorPath, err)
		}
		return report
	}

	single := filepath.Join(dir, "emSign_ECC_Root_CA_-_G3.crt")
	writeAnchor(t, single, emsign)
	if r := run(intent(single, emsignFP)); r.State != DistrustRemovalRemoved || r.DistrustEntry != "emSign ECC Root CA - G3" {
		t.Fatalf("single emSign anchor: %+v", r)
	}
	if _, err := os.Stat(single); !os.IsNotExist(err) {
		t.Fatalf("the anchor is still there: %v", err)
	}
	if r := run(intent(single, emsignFP)); r.State != DistrustRemovalAbsent {
		t.Fatalf("second removal: %+v", r)
	}

	// A bundle is the OS trust tool's to edit, never this job's.
	bundle := filepath.Join(dir, "ca-bundle.crt")
	writeAnchor(t, bundle, append(append([]byte{}, emsign...), ordinary...))
	if r := run(intent(bundle, emsignFP)); r.State != DistrustRemovalBundle {
		t.Fatalf("bundle: %+v", r)
	}
	// A certificate the host's own list does not name is never removed, even
	// when the control plane asks.
	clean := filepath.Join(dir, "clean.crt")
	writeAnchor(t, clean, ordinary)
	if r := run(intent(clean, anchorFingerprintOf(t, ordinary))); r.State != DistrustRemovalNotListed {
		t.Fatalf("an undistrusted anchor: %+v", r)
	}
	// The file holds another certificate than the finding named.
	if r := run(intent(clean, emsignFP)); r.State != DistrustRemovalDifferent {
		t.Fatalf("a different certificate: %+v", r)
	}
	for _, path := range []string{bundle, clean} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s was touched: %v", path, err)
		}
	}

	// Outside the profile's roots, or through a symlink, nothing is read or removed.
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "emsign.crt")
	writeAnchor(t, outside, emsign)
	if r := run(intent(outside, emsignFP)); r.State != DistrustRemovalRefused {
		t.Fatalf("outside the profile: %+v", r)
	}
	link := filepath.Join(dir, "emsign-link.crt")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if r := run(intent(link, emsignFP)); r.State != DistrustRemovalRefused {
		t.Fatalf("a symlink: %+v", r)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("the file behind the symlink was touched: %v", err)
	}

	// An intent that carries anchor bytes, or no finding, is not this job.
	bad := intent(single, emsignFP)
	bad.AnchorPEM = emsign
	if _, err := ExecuteDistrustedRootRemoval(profile, bad); err == nil {
		t.Fatal("an intent carrying anchor bytes was accepted")
	}
	if _, err := ExecuteDistrustedRootRemoval(profile, intent("relative/path.crt", emsignFP)); err == nil {
		t.Fatal("a relative path was accepted")
	}

	// A report must answer its intent, with the digest the agent signed.
	r := DistrustRemovalReport{FindingID: "finding-1", AnchorPath: single, Fingerprint: emsignFP, State: DistrustRemovalRemoved, DistrustEntry: "emSign ECC Root CA - G3"}
	if err := ValidateDistrustRemovalReport(intent(single, emsignFP), r, r.Digest()); err != nil {
		t.Fatal(err)
	}
	other := r
	other.FindingID = "finding-2"
	if err := ValidateDistrustRemovalReport(intent(single, emsignFP), other, other.Digest()); err == nil || !strings.Contains(err.Error(), "does not answer") {
		t.Fatalf("a report for another finding: %v", err)
	}
	if err := ValidateDistrustRemovalReport(intent(single, emsignFP), r, other.Digest()); err == nil {
		t.Fatal("a report signed with another digest was accepted")
	}
}
