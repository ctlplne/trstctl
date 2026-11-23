// SPDX-License-Identifier: BUSL-1.1

package store_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/store"
)

func TestRewrapFleetCutoverRequiresOldRoleShutdownAndOnlyCurrentBuildSessions(t *testing.T) {
	ctx := t.Context()
	admin, err := store.Open(ctx, testDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	if err := admin.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	oldRole := "r2_old_" + strings.ReplaceAll(googleuuid.NewString(), "-", "")[:20]
	newRole := "r2_new_" + strings.ReplaceAll(googleuuid.NewString(), "-", "")[:20]
	quotedOld := pgx.Identifier{oldRole}.Sanitize()
	quotedNew := pgx.Identifier{newRole}.Sanitize()
	if _, err := admin.SystemPool().Exec(ctx, "CREATE ROLE "+quotedOld+" LOGIN PASSWORD 'fixture-pass'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.SystemPool().Exec(context.Background(), "DROP ROLE IF EXISTS "+quotedOld)
	})
	if _, err := admin.SystemPool().Exec(ctx, "CREATE ROLE "+quotedNew+" LOGIN PASSWORD 'fixture-pass'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.SystemPool().Exec(context.Background(), "DROP ROLE IF EXISTS "+quotedNew)
	})
	for _, role := range []string{quotedOld, quotedNew} {
		if _, err := admin.SystemPool().Exec(ctx, "GRANT trstctl_app TO "+role); err != nil {
			t.Fatal(err)
		}
	}
	roleDSN := func(role string) string {
		t.Helper()
		parsed, err := url.Parse(testDSN)
		if err != nil {
			t.Fatal(err)
		}
		parsed.User = url.UserPassword(role, "fixture-pass")
		return parsed.String()
	}
	s, err := store.Open(ctx, roleDSN(newRole))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	cutover := store.RewrapFleetCutover{
		OldLoginRole: oldRole, NewLoginRole: newRole,
		MaintenanceAttestation: "operator-confirmed-disposable-cutover",
	}
	if err := s.RequireRewrapFleetCutover(ctx, store.RewrapFleetCutover{}); err == nil {
		t.Fatal("missing owner role and maintenance attestation was accepted")
	}
	if err := s.RequireRewrapFleetCutover(ctx, cutover); err == nil {
		t.Fatal("old role still LOGIN was accepted")
	}
	oldCfg, err := pgx.ParseConfig(roleDSN(oldRole))
	if err != nil {
		t.Fatal(err)
	}
	oldSession, err := pgx.ConnectConfig(ctx, oldCfg)
	if err != nil {
		t.Fatalf("connect disposable old role: %v", err)
	}
	defer func() { _ = oldSession.Close(context.Background()) }()
	if _, err := admin.SystemPool().Exec(ctx, "ALTER ROLE "+quotedOld+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	if reconnect, err := pgx.ConnectConfig(ctx, oldCfg); err == nil {
		_ = reconnect.Close(ctx)
		t.Fatal("the old login reconnected after NOLOGIN")
	}
	var oldVisible int
	if err := s.SystemPool().QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_stat_activity
		WHERE datname=current_database() AND usename=$1`, oldRole).Scan(&oldVisible); err != nil {
		t.Fatal(err)
	}
	if oldVisible == 0 {
		t.Fatal("the disposable old login has no observable live session")
	}
	var oldMemberSessions int
	if err := s.SystemPool().QueryRow(ctx, `SELECT count(*)
		FROM pg_catalog.pg_stat_activity AS activity
		JOIN pg_catalog.pg_roles AS login ON login.rolname=activity.usename
		WHERE datname=current_database() AND usename=$1
		AND EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members AS membership
			JOIN pg_catalog.pg_roles AS app ON app.oid=membership.roleid
			WHERE membership.member=login.oid AND app.rolname='trstctl_app')`, oldRole).Scan(&oldMemberSessions); err != nil {
		t.Fatal(err)
	}
	if oldMemberSessions != oldVisible {
		t.Fatalf("old login session inventory omitted its app-role membership: visible=%d member=%d", oldVisible, oldMemberSessions)
	}
	if err := s.RequireRewrapFleetCutover(ctx, cutover); err == nil {
		t.Fatal("old role with a live session was accepted after NOLOGIN")
	}
	if err := oldSession.Close(ctx); err != nil {
		t.Fatal(err)
	}
	spoofCfg, err := pgx.ParseConfig(roleDSN(newRole))
	if err != nil {
		t.Fatal(err)
	}
	if spoofCfg.RuntimeParams == nil {
		spoofCfg.RuntimeParams = map[string]string{}
	}
	spoofCfg.RuntimeParams["application_name"] = "trstctl/unknown-build"
	spoof, err := pgx.ConnectConfig(ctx, spoofCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = spoof.Close(context.Background()) }()
	if err := s.RequireRewrapFleetCutover(ctx, cutover); err == nil {
		t.Fatal("unknown build label on a live application session was accepted")
	}
	if err := spoof.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.RequireRewrapFleetCutover(ctx, cutover); err != nil {
		t.Fatalf("verified disposable-role cutover refused: %v", err)
	}
	midRole := "r2_mid_" + strings.ReplaceAll(googleuuid.NewString(), "-", "")[:20]
	indirectRole := "r2_indirect_" + strings.ReplaceAll(googleuuid.NewString(), "-", "")[:20]
	quotedMid := pgx.Identifier{midRole}.Sanitize()
	quotedIndirect := pgx.Identifier{indirectRole}.Sanitize()
	if _, err := admin.SystemPool().Exec(ctx, "CREATE ROLE "+quotedMid+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.SystemPool().Exec(context.Background(), "DROP ROLE IF EXISTS "+quotedMid) })
	if _, err := admin.SystemPool().Exec(ctx, "CREATE ROLE "+quotedIndirect+" LOGIN PASSWORD 'fixture-pass'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.SystemPool().Exec(context.Background(), "DROP ROLE IF EXISTS "+quotedIndirect) })
	if _, err := admin.SystemPool().Exec(ctx, "GRANT trstctl_app TO "+quotedMid); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.SystemPool().Exec(ctx, "GRANT "+quotedMid+" TO "+quotedIndirect); err != nil {
		t.Fatal(err)
	}
	indirectCfg, err := pgx.ParseConfig(roleDSN(indirectRole))
	if err != nil {
		t.Fatal(err)
	}
	indirect, err := pgx.ConnectConfig(ctx, indirectCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = indirect.Close(context.Background()) }()
	if err := s.RequireRewrapFleetCutover(ctx, cutover); err == nil {
		t.Fatal("an indirectly authorized application login with an unknown build label was accepted")
	}
	if err := indirect.Close(ctx); err != nil {
		t.Fatal(err)
	}
	wrong := cutover
	wrong.NewLoginRole = oldRole
	if err := s.RequireRewrapFleetCutover(ctx, wrong); err == nil {
		t.Fatal("identical old/new roles were accepted")
	}
	wrong = cutover
	wrong.MaintenanceAttestation = ""
	if err := s.RequireRewrapFleetCutover(ctx, wrong); err == nil {
		t.Fatal("absent owner maintenance attestation was accepted")
	}
}
