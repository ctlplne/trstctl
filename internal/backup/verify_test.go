// SPDX-License-Identifier: BUSL-1.1

package backup_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/backup"
)

// Verification must recompute, not read back what the manifest claims (epic J2).
//
// A manifest records a SHA for every artifact, and reading those back proves
// only that the manifest agrees with itself — which it always does, because one
// process wrote both in one pass. The failure this catches is silent: bit rot, a
// truncated copy, an artifact replaced from the wrong directory. None of them
// change the manifest, and all of them are discovered during the restore that
// was supposed to save you.

// writeBackup builds a small backup directory and returns its path.
func writeBackup(t *testing.T, contents map[string]string, required map[string]bool) string {
	t.Helper()
	dir := t.TempDir()
	var artifacts []backup.Artifact
	for name, body := range contents {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		sum, size, err := backup.HashFile(path)
		if err != nil {
			t.Fatal(err)
		}
		artifacts = append(artifacts, backup.Artifact{
			Name: name, Path: name, SHA256: sum, Bytes: size,
			Exists: true, Captured: true, Required: required[name],
		})
	}
	m := backup.NewFullManifest(artifacts)
	m.CreatedAt = time.Now().UTC()
	if err := backup.WriteFullManifest(filepath.Join(dir, backup.FullManifestName), m); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAnIntactBackupVerifies(t *testing.T) {
	t.Parallel()
	dir := writeBackup(t,
		map[string]string{"events.jsonl": "event data", "config.yaml": "config"},
		map[string]bool{"events.jsonl": true})

	report, err := backup.VerifyFullBackup(dir)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.Verified {
		t.Fatalf("an intact backup did not verify: %+v", report.Checks)
	}
	if len(report.Checks) != 2 {
		t.Errorf("checked %d artifacts, want 2", len(report.Checks))
	}
}

// THE test: a tampered artifact is caught, because the bytes were re-hashed.
func TestATamperedArtifactIsCaughtByRecomputation(t *testing.T) {
	t.Parallel()
	dir := writeBackup(t,
		map[string]string{"events.jsonl": "event data"},
		map[string]bool{"events.jsonl": true})

	// A SAME-LENGTH change. That matters: a shorter file is caught by the size
	// comparison, so a test that truncated would pass even with the checksum
	// check disabled — which a mutation showed it did. Only re-hashing catches
	// a substitution of equal length, and that is the case bit rot and a swapped
	// artifact actually look like.
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte("event dawa"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := backup.VerifyFullBackup(dir)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.Verified {
		t.Fatal("a backup whose bytes no longer match its manifest reported as verified. " +
			"Reading the recorded checksum back proves the manifest agrees with itself; only " +
			"re-hashing the bytes proves the backup will restore")
	}
	if len(report.Checks) != 1 || report.Checks[0].Detail == "" {
		t.Fatalf("the failure was not explained: %+v", report.Checks)
	}
}

// A missing artifact is caught and named.
func TestAMissingArtifactIsCaught(t *testing.T) {
	t.Parallel()
	dir := writeBackup(t,
		map[string]string{"events.jsonl": "data"},
		map[string]bool{"events.jsonl": true})
	if err := os.Remove(filepath.Join(dir, "events.jsonl")); err != nil {
		t.Fatal(err)
	}

	report, _ := backup.VerifyFullBackup(dir)
	if report.Verified {
		t.Fatal("a backup missing a required artifact reported as verified")
	}
}

// An OPTIONAL artifact failing does not condemn the backup, and is still shown.
//
// The two lead to different decisions: a backup missing a nice-to-have will
// restore, one missing the event log will not, and a surface that renders them
// identically makes an operator treat both as emergencies or neither.
func TestAnOptionalArtifactFailureIsReportedWithoutCondemningTheBackup(t *testing.T) {
	t.Parallel()
	dir := writeBackup(t,
		map[string]string{"events.jsonl": "data", "notes.txt": "optional"},
		map[string]bool{"events.jsonl": true})
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}

	report, _ := backup.VerifyFullBackup(dir)
	if !report.Verified {
		t.Error("an optional artifact's failure condemned a backup whose required artifacts are " +
			"all intact; it would still restore")
	}
	var sawFailure bool
	for _, c := range report.Checks {
		if c.Name == "notes.txt" && !c.Verified {
			sawFailure = true
		}
	}
	if !sawFailure {
		t.Error("the optional artifact's failure was not reported at all")
	}
}

// An artifact with no recorded checksum is UNVERIFIABLE, not verified.
//
// There is nothing to compare against, so calling it good would be the manifest
// agreeing with itself — and an operator reading a green page deserves to know
// how much of it was actually examined.
func TestAnArtifactWithNoChecksumIsUnverifiableRatherThanVerified(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "blob"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := backup.NewFullManifest([]backup.Artifact{{
		Name: "blob", Path: "blob", Exists: true, Captured: true, // no SHA256
	}})
	if err := backup.WriteFullManifest(filepath.Join(dir, backup.FullManifestName), m); err != nil {
		t.Fatal(err)
	}

	report, _ := backup.VerifyFullBackup(dir)
	if report.Unverifiable != 1 {
		t.Errorf("unverifiable = %d, want 1", report.Unverifiable)
	}
	for _, c := range report.Checks {
		if c.Verified {
			t.Errorf("artifact %q with no recorded checksum reported as verified", c.Name)
		}
	}
}

// An empty backup is not "verified".
//
// Green on an empty set is the most misleading answer available: there is no
// evidence either way, and a DR page saying a backup with nothing in it is
// intact would be read as reassurance.
func TestAnEmptyBackupIsNotReportedAsVerified(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := backup.WriteFullManifest(filepath.Join(dir, backup.FullManifestName),
		backup.NewFullManifest(nil)); err != nil {
		t.Fatal(err)
	}
	report, _ := backup.VerifyFullBackup(dir)
	if report.Verified {
		t.Fatal("a backup containing nothing reported as verified")
	}
}
