// SPDX-License-Identifier: BUSL-1.1

// Package storetest contains disposable PostgreSQL fixtures for integration tests.
// Production packages must not import it.
package storetest

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

type RewrapCutoverFixture struct {
	DSN     string
	Cutover store.RewrapFleetCutover
}

// ProvisionRewrapCutover creates two unique login roles in the test's own
// embedded PostgreSQL and disables the old login. The admin Store must outlive
// this fixture for exact-role cleanup.
func ProvisionRewrapCutover(t *testing.T, admin *store.Store, adminDSN string) RewrapCutoverFixture {
	t.Helper()
	ctx := t.Context()
	roleName := func(prefix string) string {
		return prefix + strings.ReplaceAll(uuid.NewString(), "-", "")[:20]
	}
	oldRole, newRole := roleName("r2_old_"), roleName("r2_new_")
	quotedOld := pgx.Identifier{oldRole}.Sanitize()
	quotedNew := pgx.Identifier{newRole}.Sanitize()
	for _, fixture := range []struct {
		quoted, attributes string
	}{{quotedOld, "LOGIN"}, {quotedNew, "LOGIN SUPERUSER"}} {
		if _, err := admin.SystemPool().Exec(ctx,
			"CREATE ROLE "+fixture.quoted+" "+fixture.attributes+" PASSWORD 'fixture-pass'"); err != nil {
			t.Fatal(err)
		}
		quoted := fixture.quoted
		t.Cleanup(func() {
			if _, err := admin.SystemPool().Exec(context.Background(), "DROP ROLE IF EXISTS "+quoted); err != nil {
				t.Errorf("drop disposable rewrap login %s: %v", quoted, err)
			}
		})
		if _, err := admin.SystemPool().Exec(ctx, "GRANT trstctl_app TO "+fixture.quoted); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.SystemPool().Exec(ctx, "ALTER ROLE "+quotedOld+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword(newRole, "fixture-pass")
	return RewrapCutoverFixture{DSN: parsed.String(), Cutover: store.RewrapFleetCutover{
		OldLoginRole: oldRole, NewLoginRole: newRole,
		MaintenanceAttestation: "disposable-test-cutover",
	}}
}

// OpenRewrapCutoverStore opens the configured Store as the new login.
func OpenRewrapCutoverStore(t *testing.T, admin *store.Store, adminDSN string) *store.Store {
	t.Helper()
	fixture := ProvisionRewrapCutover(t, admin, adminDSN)
	s, err := store.Open(t.Context(), fixture.DSN, store.WithRewrapFleetCutover(fixture.Cutover))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}
