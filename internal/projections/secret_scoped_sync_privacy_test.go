// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/privacy"
)

// A237-L5: an erasure rewrites the scoped-sync events' secret names segment by
// segment — the definition's source and destination prefixes and each applied
// item's destination key and source name — to the same placeholder the
// read-model rewrite writes, so a rebuild from the rewritten events reaches
// the rewritten rows. The definition's name, a longer segment that only starts
// with the subject, and the actors' fields keep their spelling.
func TestScopedSyncEventsRewriteSecretNameSegmentsA237L5(t *testing.T) {
	const tenant, subject = "11111111-1111-1111-1111-111111111111", "jean-luc"
	ph := privacy.Placeholder(privacy.SubjectRef(tenant, subject))
	rewrite := func(eventType string, payload any) []byte {
		t.Helper()
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		out, changed, err := events.PseudonymizeEventDataForSubject(data, tenant, subject, eventType, 1)
		if err != nil || !changed {
			t.Fatalf("%s rewrite changed=%t err=%v", eventType, changed, err)
		}
		return out
	}
	defined := SecretScopedSyncDefined{ID: "a2375000-0000-4000-8000-000000000001", Name: "jean-luc", SourcePrefix: "teams/jean-luc/",
		Target: "vault", DestinationPrefix: "people/jean-luc", KeyTransform: "path", DeleteScope: "managed", DefinedBy: "operator"}
	var gotDefined SecretScopedSyncDefined
	if err := json.Unmarshal(rewrite(EventSecretScopedSyncDefined, defined), &gotDefined); err != nil {
		t.Fatal(err)
	}
	if gotDefined.SourcePrefix != "teams/"+ph+"/" || gotDefined.DestinationPrefix != "people/"+ph || gotDefined.Name != "jean-luc" {
		t.Fatalf("defined after the rewrite = %+v; want both prefixes rewritten and the slug kept", gotDefined)
	}
	applied := SecretScopedSyncApplied{TenantEpoch: "epoch", ID: defined.ID, Target: "vault", PlanDigest: strings.Repeat("a", 64),
		AppliedBy: "operator", Items: []SecretScopedSyncAppliedItem{
			{RemoteKey: "people/jean-luc/db", SourceName: "teams/jean-luc/db", SourceVersion: 1, Action: "create", JobID: "job-1"},
			{RemoteKey: "people/shared/jean-lucy", SourceName: "teams/shared/jean-lucy", SourceVersion: 1, Action: "create", JobID: "job-2"},
		}}
	var gotApplied SecretScopedSyncApplied
	if err := json.Unmarshal(rewrite(EventSecretScopedSyncApplied, applied), &gotApplied); err != nil {
		t.Fatal(err)
	}
	first, second := gotApplied.Items[0], gotApplied.Items[1]
	if first.RemoteKey != "people/"+ph+"/db" || first.SourceName != "teams/"+ph+"/db" ||
		second.RemoteKey != "people/shared/jean-lucy" || second.SourceName != "teams/shared/jean-lucy" {
		t.Fatalf("applied items after the rewrite = %+v", gotApplied.Items)
	}
}
