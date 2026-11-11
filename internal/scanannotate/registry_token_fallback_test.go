// SPDX-License-Identifier: BUSL-1.1

package scanannotate_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/scanannotate"
	"trstctl.com/trstctl/internal/scanannotate/scanannotatetest"
)

// A174-L2: a registry behind a token server (the distribution token flow)
// and without the OCI referrers API. The annotator answers the registry's
// Bearer challenge with a token from its realm, fetched with the
// connection's username and token as basic credentials and reused for the
// repository; and since the registry does not name the subject on the put,
// it lists the referrer in the referrers tag schema's index
// (sha256-<subject>) so the referrer can be found. A retried annotation does
// not list it twice, and resolving takes it out of the index and deletes it.
func TestRegistryTokenFlowAndReferrersTagSchemaA174L2(t *testing.T) {
	stand := scanannotatetest.New(a174Token, "")
	t.Cleanup(stand.Close)
	stand.WithTokenServer("ci-annotator")
	stand.WithoutReferrersAPI()
	ctx := context.Background()
	image := stand.SeedImage("acme/web", []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}`))
	a := annotator(t, stand, "registry", "ci-annotator")
	annotation := scanannotate.Annotation{FindingID: "f1740000-0000-4000-8000-0000000000a2", Rule: "aws-access-key", DetectedAt: "2026-11-11T00:00:00Z",
		Object: scanannotate.Object{Repository: "acme/web", Digest: image}}
	made, err := a.Annotate(ctx, annotation)
	if err != nil || made.Status != scanannotate.Confirmed || !strings.Contains(made.Detail, "referrers tag sha256-") {
		t.Fatalf("annotate = %+v %v; want confirmed through the referrers tag schema", made, err)
	}
	if stand.TokenRequests() != 1 {
		t.Fatalf("token requests = %d; want one bearer reused for the repository", stand.TokenRequests())
	}
	if index := stand.ReferrersIndex("acme/web", image); !slices.Equal(index, []string{made.ProviderRef}) {
		t.Fatalf("referrers index = %v; want the referrer %s", index, made.ProviderRef)
	}
	again, err := a.Annotate(ctx, annotation)
	if err != nil || again.ProviderRef != made.ProviderRef || len(stand.ReferrersIndex("acme/web", image)) != 1 {
		t.Fatalf("a retried annotation = %+v %v, index %v; want the same referrer listed once", again, err, stand.ReferrersIndex("acme/web", image))
	}
	resolved, err := a.(scanannotate.Resolver).Resolve(ctx, annotation, made.ProviderRef)
	if err != nil || resolved.Status != scanannotate.Resolved || len(stand.ReferrersIndex("acme/web", image)) != 0 {
		t.Fatalf("resolve = %+v %v, index %v; want the referrer deleted and out of the index", resolved, err, stand.ReferrersIndex("acme/web", image))
	}

	// Wrong credentials at the token server are a refusal, not a retry loop.
	refused, closeFn, err := scanannotate.New(scanannotate.Connection{Provider: "registry", BaseURL: stand.URL(), Token: []byte("not-the-token"),
		Username: "ci-annotator", Doer: stand.Client()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeFn)
	if _, err := refused.Annotate(ctx, annotation); err == nil || scanannotate.Retryable(err) {
		t.Fatalf("annotate with refused credentials = %v; want a refusal that is not retried", err)
	}
}
