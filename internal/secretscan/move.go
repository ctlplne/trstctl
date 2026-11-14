// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
)

// Moving a leaked secret into the vault (P6). A served finding is redacted: it
// names the rule, the file and the line, never the value. The operator's CLI
// re-finds that one value in their own checkout with the same pinned gitleaks,
// unredacted, its report read from a pipe so it never touches disk, and keeps
// only the matching value; every other value the report held is wiped. A
// second run over the repository's history names every commit that still
// holds the value — the residue a cleaned file leaves behind — by location
// only.

// SecretLocation is where gitleaks found a value, never the value itself.
type SecretLocation struct {
	RuleID string `json:"rule_id"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	Commit string `json:"commit,omitempty"`
}

// MaxSecretResidue bounds the history locations one move records.
const MaxSecretResidue = 100

// maxLocateReport bounds an unredacted report read from gitleaks' stdout.
const maxLocateReport = 64 << 20

// ErrSecretNotLocated means no value in the checkout matches the finding's
// rule, file and line: the checkout is not the tree the server scanned.
var ErrSecretNotLocated = errors.New("secretscan: no value at the finding's rule, file and line in this checkout")

// LocateSecretForMove re-finds, in a local checkout, the value a finding
// names by rule, file (relative to the checkout) and line, and lists every
// history commit that still holds the same value. The caller wipes the value.
func (r *GitleaksRunner) LocateSecretForMove(ctx context.Context, checkout string, want SecretLocation) ([]byte, []SecretLocation, error) {
	if want.RuleID == "" || want.File == "" || want.Line < 1 {
		return nil, nil, fmt.Errorf("%w: the finding's rule, file and line are required", ErrInvalidScanTarget)
	}
	root, _, err := normalizeTarget(checkout, r.AllowedRoots)
	if err != nil {
		return nil, nil, err
	}
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		return nil, nil, fmt.Errorf("%w: the checkout must be a directory", ErrInvalidScanTarget)
	}
	bin, err := r.resolveBinary()
	if err != nil {
		return nil, nil, err
	}
	current, err := r.unredactedReport(ctx, bin, root, "dir")
	if err != nil {
		return nil, nil, err
	}
	defer current.wipe()
	var value []byte
	for _, f := range current {
		if f.RuleID == want.RuleID && f.StartLine == want.Line && len(f.Secret) > 0 && relativeTo(root, f.File) == want.File {
			value = bytes.Clone(f.Secret)
			break
		}
	}
	if value == nil {
		return nil, nil, ErrSecretNotLocated
	}
	residue, err := r.historyResidue(ctx, bin, root, value)
	if err != nil {
		secret.Wipe(value)
		return nil, nil, err
	}
	return value, residue, nil
}

// historyResidue lists every commit of the checkout's repository that holds
// value. A plain directory has no history, so no residue.
func (r *GitleaksRunner) historyResidue(ctx context.Context, bin, root string, value []byte) ([]SecretLocation, error) {
	top, topErr := GitTopLevel(ctx, root)
	if topErr != nil {
		return nil, nil
	}
	history, err := r.unredactedReport(ctx, bin, top, "git")
	if err != nil {
		return nil, err
	}
	defer history.wipe()
	var residue []SecretLocation
	for _, f := range history {
		if f.Commit != "" && bytes.Equal(f.Secret, value) && len(residue) < MaxSecretResidue {
			residue = append(residue, SecretLocation{RuleID: f.RuleID, File: relativeTo(top, f.File), Line: f.StartLine, Commit: f.Commit})
		}
	}
	return residue, nil
}

type unredactedFinding struct {
	RuleID    string                 `json:"RuleID"`
	File      string                 `json:"File"`
	StartLine int                    `json:"StartLine"`
	Commit    string                 `json:"Commit"`
	Secret    secretjson.StringBytes `json:"Secret"`
}

type unredactedFindings []unredactedFinding

func (fs unredactedFindings) wipe() {
	for i := range fs {
		secret.Wipe(fs[i].Secret)
	}
}

// unredactedReport runs gitleaks without redaction over target ("dir" for the
// working tree, "git" for every reachable commit) and parses the report it
// writes to stdout. Only the rule, location and secret fields are decoded; the
// matched line is never read.
func (r *GitleaksRunner) unredactedReport(ctx context.Context, bin, target, command string) (unredactedFindings, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	maxMB := r.MaxTargetMegabytes
	if maxMB <= 0 {
		maxMB = 50
	}
	args := []string{command, "--no-banner", "--exit-code", "0", "--log-level", "error",
		"--report-format", "json", "--report-path", "-", "--max-target-megabytes", fmt.Sprintf("%d", maxMB)}
	if command == "git" {
		args = append(args, "--log-opts", "--all")
	}
	args = append(args, target)
	cmd := exec.CommandContext(ctx, bin, args...) // #nosec G204 -- the pinned gitleaks binary over the operator's own checkout (CWE-78)
	cmd.Dir = target
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		cmd.Dir = filepath.Dir(target) // one export file (P6-L7)
	}
	cmd.Env = sanitizedGitleaksEnv(os.Environ())
	var out wipingBuffer
	defer out.wipe()
	var stderr limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("secretscan: gitleaks timed out after %s", timeout)
		}
		return nil, fmt.Errorf("secretscan: gitleaks failed: %w%s", err, stderr.suffix())
	}
	if out.overflow {
		return nil, errors.New("secretscan: the gitleaks report is larger than the locate limit")
	}
	var found unredactedFindings
	if err := json.Unmarshal(out.data, &found); err != nil {
		found.wipe()
		return nil, fmt.Errorf("secretscan: parse gitleaks report: %w", err)
	}
	return found, nil
}

// wipingBuffer collects a bounded stdout and wipes every array it outgrows.
type wipingBuffer struct {
	data     []byte
	overflow bool
}

func (b *wipingBuffer) Write(p []byte) (int, error) {
	if b.overflow || len(p) > maxLocateReport-len(b.data) {
		b.overflow = true
		return len(p), nil
	}
	if len(p) > cap(b.data)-len(b.data) {
		// Grow into a new array (append's growth, at least 4 KiB) and wipe the
		// one it outgrew.
		outgrown := b.data
		b.data = slices.Grow(b.data[:len(b.data):len(b.data)], max(len(p), 4096))
		secret.Wipe(outgrown[:cap(outgrown)])
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *wipingBuffer) wipe() { secret.Wipe(b.data[:cap(b.data)]) }

// relativeTo reports file relative to root when gitleaks named it absolutely.
func relativeTo(root, file string) string {
	if !filepath.IsAbs(file) {
		return filepath.ToSlash(file)
	}
	if rel, err := filepath.Rel(root, file); err == nil && rel != ".." && !filepath.IsAbs(rel) &&
		(len(rel) < 3 || rel[:3] != ".."+string(filepath.Separator)) {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(file)
}
