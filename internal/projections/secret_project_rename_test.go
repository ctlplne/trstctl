// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// TestSecretProjectRenamesKeepSlugsAcrossReplayA235L3 is A235-L3's read
// model: a project's and an environment's display names change while their
// slugs, restriction and membership stay; an older rename applied after a
// newer one changes nothing; a rebuild from the log lands on the latest
// names; an incomplete rename is refused.
func TestSecretProjectRenamesKeepSlugsAcrossReplayA235L3(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	log := openLog(t)
	projector := projections.New(s)
	apply := func(typ string, payload any) events.Event {
		t.Helper()
		e := appendJSONEvent(t, log, typ, tenantA, payload)
		if err := projector.Apply(ctx, e); err != nil {
			t.Fatalf("apply %s: %v", typ, err)
		}
		return e
	}
	apply(projections.EventTenantRegistered, map[string]string{"name": "A235-L3 rename"})
	apply(projections.EventSecretProjectCreated, projections.SecretProjectCreated{
		Slug: "pay", Name: "Payments", CreatedBy: "alice",
		Environments: []projections.SecretProjectEnvironment{{Slug: "prod", Name: "Production", Restricted: true}},
	})
	apply(projections.EventSecretProjectMemberGranted, projections.SecretProjectMemberGranted{
		Project: "pay", Subject: "bob", Role: "developer", Environments: []string{"prod"}, GrantedBy: "alice",
	})
	first := apply(projections.EventSecretProjectRenamed, projections.SecretProjectRenamed{Project: "pay", Name: "Payments API", RenamedBy: "alice"})
	apply(projections.EventSecretProjectEnvironmentRenamed, projections.SecretProjectEnvironmentRenamed{
		Project: "pay", Environment: "prod", Name: "Live", RenamedBy: "alice",
	})
	apply(projections.EventSecretProjectRenamed, projections.SecretProjectRenamed{Project: "pay", Name: "Payments Platform", RenamedBy: "carol"})

	check := func(stage string) {
		t.Helper()
		p, envs, members, err := s.GetSecretProject(ctx, tenantA, "pay")
		if err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
		if p.Slug != "pay" || p.Name != "Payments Platform" || len(envs) != 1 || envs[0].Slug != "prod" || envs[0].Name != "Live" || !envs[0].Restricted {
			t.Fatalf("%s: project %+v environments %+v", stage, p, envs)
		}
		if len(members) != 1 || members[0].Subject != "bob" || len(members[0].Environments) != 1 || members[0].Environments[0] != "prod" {
			t.Fatalf("%s: members %+v", stage, members)
		}
	}
	check("applied")

	// The first rename, applied again after the later one, changes nothing.
	if err := s.WithTenantProjection(ctx, tenantA, func(tx pgx.Tx) error {
		return s.ApplySecretProjectRenamedTx(ctx, tx, tenantA, "pay", "Payments API", first.Sequence)
	}); err != nil {
		t.Fatal(err)
	}
	check("older rename out of order")

	if err := projections.New(s).Rebuild(ctx, log); err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	check("rebuilt")

	bad := appendJSONEvent(t, log, projections.EventSecretProjectEnvironmentRenamed, tenantA,
		projections.SecretProjectEnvironmentRenamed{Project: "pay", Name: "Nameless", RenamedBy: "alice"})
	if err := projector.Apply(ctx, bad); err == nil {
		t.Fatal("an environment rename that names no environment was applied")
	}
}
