// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"path/filepath"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/scanannotate"
	"trstctl.com/trstctl/internal/secretscan"
)

// repositoryFileObject is where a first-party repository scan saw a
// credential, as a code scanning upload names it (A174-L5): the repository,
// commit and ref of the push, and the file (relative to the repository root)
// and line. nil when the scan has no annotation connection or the file
// cannot be named inside the repository.
func repositoryFileObject(cfg secretscan.RepositoryScanConfig, root string, f secretscan.Finding) map[string]string {
	if cfg.AnnotationProvider() == "" || f.Line < 1 {
		return nil
	}
	path := filepath.Clean(strings.TrimSpace(f.File))
	if filepath.IsAbs(path) {
		rel, err := filepath.Rel(filepath.Clean(root), path)
		if err != nil {
			return nil
		}
		path = rel
	}
	path = filepath.ToSlash(path)
	if path == "." || path == ".." || strings.HasPrefix(path, "../") {
		return nil
	}
	return map[string]string{"kind": scanannotate.ObjectKindRepositoryFile, "repo": cfg.Repository, "commit_sha": cfg.CommitSHA,
		"ref": cfg.Ref, "path": path, "line": strconv.Itoa(f.Line)}
}
