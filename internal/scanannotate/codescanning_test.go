// SPDX-License-Identifier: BUSL-1.1

package scanannotate_test

import (
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/scanannotate"
	"trstctl.com/trstctl/internal/scanannotate/scanannotatetest"
)

// A174-L5: a repository finding is written back as a GitHub code scanning
// analysis of its own: the rule, the file and the line under the finding's
// category, never a secret; a retried upload replaces the same analysis, and
// resolving the finding uploads its category with no result.
func TestCodeScanningUploadIsTheFindingsOwnAnalysisA174L5(t *testing.T) {
	stand := scanannotatetest.New(a174Token, "")
	t.Cleanup(stand.Close)
	ctx := context.Background()
	stand.SeedCommit("github", "acme/api", "c174c174c174c174")
	github := annotator(t, stand, "github", "")
	const finding = "f1740005-0000-4000-8000-000000000001"
	a := scanannotate.Annotation{FindingID: finding, Rule: "gitlab-pat", Object: scanannotate.Object{Kind: scanannotate.ObjectKindRepositoryFile,
		Repo: "acme/api", CommitSHA: "c174c174c174c174", Ref: "refs/heads/main", Path: "config/deploy.env", Line: "3"}}
	category := scanannotate.CodeScanningCategory(finding)

	got, err := github.Annotate(ctx, a)
	if err != nil || got.Status != scanannotate.Confirmed || got.ProviderRef != "code-scanning:sarif-1" {
		t.Fatalf("upload = %+v %v", got, err)
	}
	results, ok := stand.CodeScanning("acme/api", category)
	if !ok || len(results) != 1 || results[0].Rule != "gitlab-pat" || results[0].Path != "config/deploy.env" || results[0].Line != 3 ||
		!strings.Contains(results[0].Message, scanannotate.Marker(finding)) {
		t.Fatalf("analysis = %+v (%v)", results, ok)
	}
	if len(stand.Statuses("github", "acme/api", "c174c174c174c174")) != 0 {
		t.Fatal("a repository finding set a commit status")
	}
	// A retry replaces the same analysis.
	a.Retry = true
	if got, err := github.Annotate(ctx, a); err != nil || got.Status != scanannotate.Confirmed {
		t.Fatalf("retry = %+v %v", got, err)
	}
	if results, _ := stand.CodeScanning("acme/api", category); len(results) != 1 || stand.SARIFUploads() != 2 {
		t.Fatalf("after the retry = %+v, %d uploads", results, stand.SARIFUploads())
	}
	// Resolving uploads the category with no result.
	resolver, ok := github.(scanannotate.Resolver)
	if !ok {
		t.Fatal("github annotations cannot be resolved")
	}
	if got, err := resolver.Resolve(ctx, a, "code-scanning:sarif-2"); err != nil || got.Status != scanannotate.Resolved {
		t.Fatalf("resolve = %+v %v", got, err)
	}
	if results, ok := stand.CodeScanning("acme/api", category); !ok || len(results) != 0 {
		t.Fatalf("after resolving = %+v (%v); want an empty analysis", results, ok)
	}

	for name, object := range map[string]scanannotate.Object{
		"no ref":  {Kind: scanannotate.ObjectKindRepositoryFile, Repo: "acme/api", CommitSHA: "c174c174c174c174", Path: "a.env", Line: "1"},
		"no path": {Kind: scanannotate.ObjectKindRepositoryFile, Repo: "acme/api", CommitSHA: "c174c174c174c174", Ref: "refs/heads/main"},
		"no repo": {Kind: scanannotate.ObjectKindRepositoryFile, CommitSHA: "c174c174c174c174", Ref: "refs/heads/main", Path: "a.env"},
	} {
		if _, err := github.Annotate(ctx, scanannotate.Annotation{FindingID: finding, Rule: "r", Object: object}); err == nil || scanannotate.Retryable(err) {
			t.Fatalf("%s: %v; want a final refusal", name, err)
		}
	}
	unknown := a
	unknown.Object.CommitSHA = "d174d174d174d174"
	if _, err := github.Annotate(ctx, unknown); err == nil || scanannotate.Retryable(err) || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("an unknown commit = %v; want a final 404", err)
	}
}
