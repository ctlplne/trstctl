// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"bytes"
	"context"
	"fmt"
	"os"
)

// Moving a third-party leak into the vault (P6-L7). A Slack, Jira, CI-log or
// registry finding names its rule, a file inside the export the scan read and
// a line, never the value. The operator's CLI re-finds that one value in its
// own copy of the same export (the directory or the one file the scan read)
// with the pinned gitleaks, its report read from a pipe; every other value
// the report held is wiped. An export has no git history, so a third-party
// move records no history residue.

// LocateSecretInExport re-finds, in a local copy of a scanned third-party
// export, the value a finding names by rule, file (as the scan recorded it,
// inside the export) and line. The caller wipes the value.
func (r *GitleaksRunner) LocateSecretInExport(ctx context.Context, export string, want SecretLocation) ([]byte, error) {
	if want.RuleID == "" || want.File == "" || want.Line < 1 {
		return nil, fmt.Errorf("%w: the finding's rule, file and line are required", ErrInvalidScanTarget)
	}
	target, _, err := normalizeTarget(export, r.AllowedRoots)
	if err != nil {
		return nil, err
	}
	file, ok := exportFile(target, want.File)
	if !ok {
		return nil, ErrSecretNotLocated
	}
	if info, err := os.Stat(file); err != nil || info.IsDir() {
		return nil, ErrSecretNotLocated // not the export the scan read
	}
	bin, err := r.resolveBinary()
	if err != nil {
		return nil, err
	}
	found, err := r.unredactedReport(ctx, bin, file, "dir")
	if err != nil {
		return nil, err
	}
	defer found.wipe()
	for _, f := range found {
		if f.RuleID == want.RuleID && f.StartLine == want.Line && len(f.Secret) > 0 {
			return bytes.Clone(f.Secret), nil
		}
	}
	return nil, ErrSecretNotLocated
}
