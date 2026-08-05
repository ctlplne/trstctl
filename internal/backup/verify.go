// SPDX-License-Identifier: MPL-2.0

package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Checking a backup by recomputing it, not by reading what it claims (epic J2).
//
// A manifest records a SHA-256 for every artifact. Reading those back and
// reporting "integrity: ok" would be checking that the manifest agrees with
// itself, which it always does — the file was written in one pass by the process
// that computed the hashes.
//
// The only statement worth serving is one produced by hashing the bytes on disk
// again and comparing. That is the difference between "this backup says it is
// intact" and "this backup is intact", and it is the whole reason an operator
// looks at a DR page.
//
// The distinction has teeth because the failure it catches is silent: bit rot,
// a truncated copy, an artifact restored from the wrong directory. None of those
// change the manifest, and all of them are discovered during the restore that
// was supposed to save you.

// ArtifactCheck is one artifact's verification result.
type ArtifactCheck struct {
	Name string `json:"name"`
	// Verified is true only when the bytes on disk were hashed and matched.
	Verified bool `json:"verified"`
	// Detail says what went wrong, in terms an operator can act on.
	Detail string `json:"detail,omitempty"`
	// Required marks an artifact the deployment cannot be restored without.
	// A failed optional artifact is a warning; a failed required one means this
	// backup will not restore, and the two must not be shown the same way.
	Required bool `json:"required"`
}

// VerifyReport is what a recomputation found.
type VerifyReport struct {
	// ManifestPath is what was checked.
	ManifestPath string `json:"manifest_path"`
	// CreatedAt is when the backup was taken, from its manifest.
	CreatedAt time.Time `json:"created_at"`
	// Checks is every artifact, verified or not.
	Checks []ArtifactCheck `json:"checks"`
	// Verified is true only when every REQUIRED artifact re-hashed correctly.
	//
	// Not "no errors": an optional artifact that failed leaves this true and is
	// still reported, because a backup missing a nice-to-have will restore and
	// one missing the event log will not.
	Verified bool `json:"verified"`
	// Unverifiable counts artifacts recorded with no hash to check against.
	//
	// Its own number rather than folded into failures. An artifact the backup
	// never hashed is not corrupt — it is unchecked, and an operator reading a
	// green page deserves to know how much of it was actually examined.
	Unverifiable int `json:"unverifiable"`
}

// VerifyFullBackup re-hashes every artifact in a backup directory.
//
// dir is the directory holding the manifest. Nothing is restored and nothing is
// written: this reads bytes and computes, so it is safe to run against a live
// backup on a schedule.
func VerifyFullBackup(dir string) (VerifyReport, error) {
	manifestPath := filepath.Join(dir, FullManifestName)
	m, err := ReadFullManifest(manifestPath)
	if err != nil {
		return VerifyReport{ManifestPath: manifestPath}, err
	}
	report := VerifyReport{
		ManifestPath: manifestPath, CreatedAt: m.CreatedAt, Verified: true,
	}
	for _, artifact := range m.Artifacts {
		if !artifact.Captured {
			// Not in the backup at all. That is a fact about what was taken
			// rather than a corruption, and conflating them would make every
			// partial backup look damaged.
			continue
		}
		check := ArtifactCheck{Name: artifact.Name, Required: artifact.Required}
		path := filepath.Join(dir, artifact.Path)

		info, statErr := os.Stat(path)
		switch {
		case statErr != nil:
			check.Detail = "the manifest lists this artifact and it is not in the backup directory"
		case artifact.SHA256 == "":
			// Recorded without a hash. Reported as unverifiable rather than
			// verified: there is nothing to compare against, and calling it
			// good would be the manifest agreeing with itself again.
			check.Detail = "the manifest records no checksum for this artifact, so its bytes " +
				"cannot be checked"
			report.Unverifiable++
		default:
			var (
				sum   string
				bytes int64
				hErr  error
			)
			if info.IsDir() {
				sum, bytes, hErr = HashTree(path)
			} else {
				sum, bytes, hErr = HashFile(path)
			}
			switch {
			case hErr != nil:
				check.Detail = fmt.Sprintf("could not read this artifact to check it: %v", hErr)
			case sum != artifact.SHA256:
				check.Detail = "the bytes on disk do not match the checksum recorded when this " +
					"backup was taken; the artifact has changed or been replaced since"
			case artifact.Bytes != 0 && bytes != artifact.Bytes:
				check.Detail = fmt.Sprintf("size is %d bytes, the manifest recorded %d", bytes, artifact.Bytes)
			default:
				check.Verified = true
			}
		}
		if !check.Verified && check.Required {
			// A required artifact that did not re-hash means this backup will
			// not restore. An optional one that failed is reported and does not
			// change the verdict, because the two lead to different decisions.
			report.Verified = false
		}
		report.Checks = append(report.Checks, check)
	}
	sort.Slice(report.Checks, func(i, j int) bool { return report.Checks[i].Name < report.Checks[j].Name })
	if len(report.Checks) == 0 {
		// A manifest listing nothing captured cannot be called verified: there
		// is no evidence either way, and green on an empty set is the most
		// misleading answer available.
		report.Verified = false
	}
	return report, nil
}
