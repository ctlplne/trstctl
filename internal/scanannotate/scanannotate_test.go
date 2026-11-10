// SPDX-License-Identifier: BUSL-1.1

package scanannotate_test

import (
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/scanannotate"
	"trstctl.com/trstctl/internal/scanannotate/scanannotatetest"
)

const a174Token = "a174-annotation-token" // #nosec G101 -- fabricated fixture credential (CWE-798)

func annotator(t *testing.T, stand *scanannotatetest.Stand, provider, username string) scanannotate.Annotator {
	t.Helper()
	a, closeFn, err := scanannotate.New(scanannotate.Connection{Provider: provider, BaseURL: stand.URL(), Token: []byte(a174Token),
		Username: username, Doer: stand.Client()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeFn)
	return a
}

func TestAnnotationsLandAtEachProviderOnceAndCarryNoSecret(t *testing.T) {
	stand := scanannotatetest.New(a174Token, "ops@example.com")
	t.Cleanup(stand.Close)
	ctx := context.Background()
	stand.SeedSlackMessage("C0A174", "1730000000.000100")
	stand.SeedJiraIssue("OPS-174")
	stand.SeedCommit("github", "acme/api", "a174a174a174")
	stand.SeedCommit("gitlab", "acme/api", "b174b174b174")
	image := stand.SeedImage("acme/api", []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}`))
	base := scanannotate.Annotation{FindingID: "f1740000-0000-4000-8000-000000000001", Rule: "slack-bot-token", DetectedAt: "2026-11-01T00:00:00Z"}

	steps := []struct {
		provider, username string
		object             scanannotate.Object
		check              func() []string
	}{
		{"slack", "", scanannotate.Object{ChannelID: "C0A174", MessageTS: "1730000000.000100"}, func() []string { return stand.SlackReplies("C0A174", "1730000000.000100") }},
		{"jira", "ops@example.com", scanannotate.Object{IssueKey: "OPS-174"}, func() []string { return stand.JiraComments("OPS-174") }},
		{"github", "", scanannotate.Object{Repo: "acme/api", CommitSHA: "a174a174a174"}, func() []string {
			var out []string
			for _, s := range stand.Statuses("github", "acme/api", "a174a174a174") {
				out = append(out, s.State+" "+s.Context+" "+s.Description)
			}
			return out
		}},
		{"gitlab", "", scanannotate.Object{Repo: "acme/api", CommitSHA: "b174b174b174"}, func() []string {
			var out []string
			for _, s := range stand.Statuses("gitlab", "acme/api", "b174b174b174") {
				out = append(out, s.State+" "+s.Context+" "+s.Description)
			}
			return out
		}},
		{"registry", "", scanannotate.Object{Repository: "acme/api", Digest: image}, func() []string {
			var out []string
			for _, a := range stand.Referrers("acme/api", image) {
				out = append(out, a["dev.trstctl.finding.id"]+" "+a["dev.trstctl.finding.rule"]+" "+a["dev.trstctl.finding.message"])
			}
			return out
		}},
	}
	for _, step := range steps {
		a := base
		a.Object = step.object
		ann := annotator(t, stand, step.provider, step.username)
		res, err := ann.Annotate(ctx, a)
		if err != nil || res.Status != scanannotate.Confirmed || res.ProviderRef == "" {
			t.Fatalf("%s annotate = %+v, %v", step.provider, res, err)
		}
		notes := step.check()
		if len(notes) != 1 || !strings.Contains(notes[0], "slack-bot-token") || !strings.Contains(notes[0], "f1740000") {
			t.Fatalf("%s notes = %v", step.provider, notes)
		}
		// A retried delivery converges on the one note.
		a.Retry = true
		res, err = ann.Annotate(ctx, a)
		if err != nil {
			t.Fatalf("%s retry: %v", step.provider, err)
		}
		if notes := step.check(); step.provider != "github" && len(notes) != 1 {
			t.Fatalf("%s retry wrote again: %v (%+v)", step.provider, notes, res)
		}
	}
	if stand.Unauthorized() != 0 {
		t.Fatalf("the stand-in refused %d requests", stand.Unauthorized())
	}
}

func TestAnnotationFailuresSayWhetherToRetry(t *testing.T) {
	stand := scanannotatetest.New(a174Token, "")
	t.Cleanup(stand.Close)
	ctx := context.Background()
	stand.SeedSlackMessage("C0A174", "1.0")
	slack := annotator(t, stand, "slack", "")

	stand.SlackLimitNext(1)
	_, err := slack.Annotate(ctx, scanannotate.Annotation{FindingID: "f2", Rule: "r", Object: scanannotate.Object{ChannelID: "C0A174", MessageTS: "1.0"}})
	if !scanannotate.Retryable(err) {
		t.Fatalf("ratelimited = %v, want retryable", err)
	}
	_, err = slack.Annotate(ctx, scanannotate.Annotation{FindingID: "f3", Rule: "r", Object: scanannotate.Object{ChannelID: "C0GONE", MessageTS: "9.9"}})
	if err == nil || scanannotate.Retryable(err) || !strings.Contains(err.Error(), "thread_not_found") {
		t.Fatalf("missing thread = %v, want a final refusal", err)
	}
	_, err = annotator(t, stand, "jira", "").Annotate(ctx, scanannotate.Annotation{FindingID: "f4", Rule: "r", Object: scanannotate.Object{IssueKey: "NOPE-1"}})
	if err == nil || scanannotate.Retryable(err) || !strings.Contains(err.Error(), "status 404") {
		t.Fatalf("missing issue = %v", err)
	}
	_, err = annotator(t, stand, "github", "").Annotate(ctx, scanannotate.Annotation{FindingID: "f5", Rule: "r"})
	if err == nil || scanannotate.Retryable(err) {
		t.Fatalf("no target = %v", err)
	}
	wrong, closeFn, err := scanannotate.New(scanannotate.Connection{Provider: "slack", BaseURL: stand.URL(), Token: []byte("wrong"), Doer: stand.Client()})
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	_, err = wrong.Annotate(ctx, scanannotate.Annotation{FindingID: "f6", Rule: "r", Object: scanannotate.Object{ChannelID: "C0A174", MessageTS: "1.0"}})
	if err == nil || scanannotate.Retryable(err) || !strings.Contains(err.Error(), "status 401") {
		t.Fatalf("wrong token = %v", err)
	}
	if _, _, err := scanannotate.New(scanannotate.Connection{Provider: "teams", BaseURL: stand.URL(), Token: []byte("x"), Doer: stand.Client()}); err == nil {
		t.Fatal("an unknown provider was accepted")
	}
}

// A174-L1: each provider settles a resolved finding's annotation the way it
// can, and settling it again answers that it is already settled.
func TestResolveSettlesEachProvidersAnnotation(t *testing.T) {
	stand := scanannotatetest.New(a174Token, "ops@example.com")
	t.Cleanup(stand.Close)
	ctx := context.Background()
	stand.SeedSlackMessage("C0A174", "1730000000.000100")
	stand.SeedJiraIssue("OPS-174")
	stand.SeedCommit("github", "acme/api", "a174a174a174")
	stand.SeedCommit("gitlab", "acme/api", "b174b174b174")
	image := stand.SeedImage("acme/api", []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}`))
	base := scanannotate.Annotation{FindingID: "f1740000-0000-4000-8000-000000000002", Rule: "slack-bot-token", DetectedAt: "2026-11-01T00:00:00Z"}
	for _, step := range []struct {
		provider, username string
		object             scanannotate.Object
		settled            func() bool
	}{
		{"slack", "", scanannotate.Object{ChannelID: "C0A174", MessageTS: "1730000000.000100"}, func() bool {
			return len(stand.SlackReplies("C0A174", "1730000000.000100")) == 0
		}},
		{"jira", "ops@example.com", scanannotate.Object{IssueKey: "OPS-174"}, func() bool {
			c := stand.JiraComments("OPS-174")
			return len(c) == 1 && strings.Contains(c[0], "Resolved in trstctl")
		}},
		{"github", "", scanannotate.Object{Repo: "acme/api", CommitSHA: "a174a174a174"}, func() bool {
			s := stand.Statuses("github", "acme/api", "a174a174a174")
			return len(s) == 2 && s[1].State == "success" && s[1].Context == s[0].Context
		}},
		{"gitlab", "", scanannotate.Object{Repo: "acme/api", CommitSHA: "b174b174b174"}, func() bool {
			s := stand.Statuses("gitlab", "acme/api", "b174b174b174")
			return len(s) == 2 && s[1].State == "success" && s[1].Context == s[0].Context
		}},
		{"registry", "", scanannotate.Object{Repository: "acme/api", Digest: image}, func() bool {
			return len(stand.Referrers("acme/api", image)) == 0
		}},
	} {
		a := annotator(t, stand, step.provider, step.username)
		annotation := base
		annotation.Object = step.object
		made, err := a.Annotate(ctx, annotation)
		if err != nil {
			t.Fatalf("%s annotate: %v", step.provider, err)
		}
		resolver, ok := a.(scanannotate.Resolver)
		if !ok {
			t.Fatalf("%s annotations cannot be settled", step.provider)
		}
		got, err := resolver.Resolve(ctx, annotation, made.ProviderRef)
		if err != nil || got.Status != scanannotate.Resolved || !step.settled() {
			t.Fatalf("%s resolve = %+v, %v (settled %v)", step.provider, got, err, step.settled())
		}
		if strings.Contains(got.Detail, a174Token) {
			t.Fatalf("%s resolve detail carries the token", step.provider)
		}
		if step.provider == "slack" || step.provider == "registry" {
			again, err := resolver.Resolve(ctx, annotation, made.ProviderRef)
			if err != nil || again.Status != scanannotate.AlreadyResolved {
				t.Fatalf("%s resolved again = %+v, %v; want already resolved", step.provider, again, err)
			}
		}
	}
}
