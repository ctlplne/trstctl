// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
)

// Re-checking a moved secret's history residue (P6-L5). A move records the
// history commits that held the value when it moved. Every later completed
// scan of the repository looks again: the server deepens its shallow clone
// to every branch's full history, runs the pinned gitleaks over it unredacted
// (the report read from a pipe, never written) and compares each value found
// with the moved values in memory. A commit a history rewrite removed drops
// off; one that brings the value back is added. Only locations leave.

// ErrNoHistory means a scan target has no git history to re-check.
var ErrNoHistory = errors.New("secretscan: the scan target has no git history")

// DeepenClone fetches every branch's full history into a clone
// PrepareRepositoryTargetWithCredential made (clone_url mode), authenticated
// as the clone was. A checkout_path target is re-checked as it is.
func DeepenClone(ctx context.Context, target RepositoryTarget, cfg RepositoryScanConfig, cred *RepositoryCredential) error {
	if target.Mode != "clone_url" {
		return nil
	}
	var auth []string
	if cred != nil {
		var err error
		if auth, err = credentialGitConfig(strings.TrimSpace(cfg.CloneURL), cred); err != nil {
			return err
		}
	}
	shallow, err := gitOutput(ctx, target.Path, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return fmt.Errorf("secretscan: %w", err)
	}
	args := []string{"fetch", "--no-tags", "--quiet"}
	if strings.TrimSpace(string(shallow)) == "true" {
		args = append(args, "--unshallow")
	}
	return runGit(ctx, target.Path, auth, append(args, "--", "origin", "+refs/heads/*:refs/remotes/origin/*")...)
}

// HistoryResidueOf lists, for each of values, every commit reachable in the
// repository at dir that still holds it, by location (at most
// MaxSecretResidue each). dir is the scan root for this run alone; the values
// are compared in memory and the caller wipes them. A directory with no git
// history is ErrNoHistory.
func (r *GitleaksRunner) HistoryResidueOf(ctx context.Context, dir string, values [][]byte) ([][]SecretLocation, error) {
	confined := *r
	confined.AllowedRoots = []string{dir}
	root, _, err := normalizeTarget(dir, confined.AllowedRoots)
	if err != nil {
		return nil, err
	}
	top, err := GitTopLevel(ctx, root)
	if err != nil {
		return nil, ErrNoHistory
	}
	bin, err := confined.resolveBinary()
	if err != nil {
		return nil, err
	}
	history, err := confined.unredactedReport(ctx, bin, top, "git")
	if err != nil {
		return nil, err
	}
	defer history.wipe()
	out := make([][]SecretLocation, len(values))
	for _, f := range history {
		if f.Commit == "" || len(f.Secret) == 0 {
			continue
		}
		for i, value := range values {
			if len(value) > 0 && bytes.Equal(f.Secret, value) && len(out[i]) < MaxSecretResidue {
				out[i] = append(out[i], SecretLocation{RuleID: f.RuleID, File: relativeTo(top, f.File), Line: f.StartLine, Commit: f.Commit})
			}
		}
	}
	return out, nil
}
