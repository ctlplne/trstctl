// SPDX-License-Identifier: BUSL-1.1

package secretscan

import (
	"strings"
	"testing"
)

// A174-L5: a repository scan's annotation is a GitHub code scanning
// connection for the scan's own commit and ref; nothing else is taken.
func TestRepositoryAnnotationIsAGitHubCodeScanningConnectionA174L5(t *testing.T) {
	conn := func() *AnnotationConfig {
		return &AnnotationConfig{BaseURL: "https://api.github.com", TokenRef: "env:GITHUB_SECURITY_EVENTS_TOKEN"} // #nosec G101 -- a credential reference to a fabricated fixture (CWE-798)
	}
	ok := RepositoryScanConfig{Provider: "github", Repository: "acme/api", Ref: "refs/heads/main", CommitSHA: "c174c174c174c174", Annotation: conn()}
	if err := ValidateRepositoryAnnotation(ok); err != nil || ok.AnnotationProvider() != "github" {
		t.Fatalf("a GitHub push = %v (%q)", err, ok.AnnotationProvider())
	}
	if err := ValidateRepositoryAnnotation(RepositoryScanConfig{Provider: "gitlab"}); err != nil {
		t.Fatalf("no annotation = %v", err)
	}
	for name, tc := range map[string]struct {
		cfg  RepositoryScanConfig
		want string
	}{
		"gitlab":         {RepositoryScanConfig{Provider: "gitlab", Ref: "refs/heads/main", CommitSHA: "c174c174", Annotation: conn()}, "only GitHub"},
		"bitbucket":      {RepositoryScanConfig{Provider: "bitbucket", Ref: "refs/heads/main", CommitSHA: "c174c174", Annotation: conn()}, "only GitHub"},
		"names a commit": {RepositoryScanConfig{Provider: "github", Ref: "refs/heads/main", CommitSHA: "c174c174", Annotation: &AnnotationConfig{BaseURL: "https://api.github.com", TokenRef: "env:T", CommitSHA: "d174d174"}}, "names only its connection"},
		"no commit":      {RepositoryScanConfig{Provider: "github", Ref: "refs/heads/main", Annotation: conn()}, "commit_sha"},
		"bare branch":    {RepositoryScanConfig{Provider: "github", Ref: "main", CommitSHA: "c174c174", Annotation: conn()}, "ref"},
		"plain http":     {RepositoryScanConfig{Provider: "github", Ref: "refs/heads/main", CommitSHA: "c174c174", Annotation: &AnnotationConfig{BaseURL: "http://api.github.com", TokenRef: "env:T"}}, "https"},
		"no token":       {RepositoryScanConfig{Provider: "github", Ref: "refs/heads/main", CommitSHA: "c174c174", Annotation: &AnnotationConfig{BaseURL: "https://api.github.com"}}, "token_ref"},
	} {
		if err := ValidateRepositoryAnnotation(tc.cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s = %v; want %q", name, err, tc.want)
		}
	}
	if (RepositoryScanConfig{Provider: "gitlab", Annotation: conn()}).AnnotationProvider() != "" {
		t.Fatal("a GitLab scan names an annotation provider")
	}
}
