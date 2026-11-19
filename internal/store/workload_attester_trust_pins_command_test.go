// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/githubidentity"
	"trstctl.com/trstctl/internal/store"
)

// CR-384: when a command claims the source, its current issuer and immutable
// pins govern the write even if the request used an earlier read model.
func TestClaimTrustCommandChecksCurrentGitHubPinAuthority(t *testing.T) {
	s := newStore(t)
	seedTwoTenants(t, s)
	ctx := t.Context()
	for i, tc := range []struct {
		name, issuer, requestedIssuer, kind string
		allowed                             bool
		admission                           store.WorkloadAttesterTrustUpsertAdmission
	}{
		{
			name: "stale rotation after issuer replacement", issuer: "https://git.example.test",
			requestedIssuer: githubidentity.DefaultIssuer, kind: "workload.attester_trust_source.rotated",
		},
		{
			name: "stale full replacement after pins added", issuer: githubidentity.DefaultIssuer,
			requestedIssuer: githubidentity.DefaultIssuer, kind: "workload.attester_trust_source.upserted",
		},
		{
			name: "create cannot replace a newly pinned source", issuer: githubidentity.DefaultIssuer,
			requestedIssuer: githubidentity.DefaultIssuer, kind: "workload.attester_trust_source.upserted",
			admission: store.WorkloadAttesterTrustUpsertAdmission{Create: true, PinsExplicit: true},
		},
		{
			name: "operator explicitly clears ordinary pins", issuer: githubidentity.DefaultIssuer,
			requestedIssuer: githubidentity.DefaultIssuer, kind: "workload.attester_trust_source.upserted",
			admission: store.WorkloadAttesterTrustUpsertAdmission{PinsExplicit: true}, allowed: true,
		},
		{
			name: "explicit GitHub issuer matches default", issuer: "", requestedIssuer: githubidentity.DefaultIssuer,
			kind: "workload.attester_trust_source.rotated", allowed: true,
		},
		{
			name: "configured GitHub issuer stays the same", issuer: "https://git.example.test",
			requestedIssuer: "https://git.example.test", kind: "workload.attester_trust_source.rotated", allowed: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sourceID := uuid(tenantA, 38410+i)
			if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				return s.ApplyWorkloadAttesterTrustSourceUpsertedTx(ctx, tx, store.WorkloadAttesterTrustSource{
					TenantID: tenantA, ID: sourceID, Name: tc.name, Method: "github_oidc",
					Issuer: tc.issuer, Enabled: true, AllowedOwnerIDs: []string{"123"},
				})
			}); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(map[string]any{
				"id": sourceID, "issuer": tc.requestedIssuer, "method": "github_oidc", "enabled": true,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.ClaimWorkloadAttesterTrustCommand(ctx, store.WorkloadAttesterTrustCommand{
				SourceID: sourceID, BindingSHA256: strings.Repeat("a", 64), RequestBinding: strings.Repeat("b", 64),
				UpsertAdmission: tc.admission,
				Event: events.Event{
					ID: uuid(tenantA, 38420+i), Type: tc.kind, TenantID: tenantA,
					SchemaVersion: events.DefaultSchemaVersion, Time: time.Now().UTC().Truncate(time.Microsecond), Data: data,
				},
			})
			if (err == nil) != tc.allowed {
				t.Fatalf("claimed = %t, want %t, error %v", err == nil, tc.allowed, err)
			}
			current, err := s.GetEffectiveWorkloadAttesterTrustSource(ctx, tenantA, sourceID)
			if err != nil || current.AuthorityPending != tc.allowed || !current.HasImmutableGitHubPins() {
				t.Fatalf("unexpected effective source state after claim, pending=%t, error %v", current.AuthorityPending, err)
			}
		})
	}
}
