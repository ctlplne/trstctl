// SPDX-License-Identifier: LicenseRef-trstctl-EE

//go:build trstctl_core

package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	corestore "trstctl.com/trstctl/internal/store"

	agidstore "trstctl.com/trstctl/ee/agentid/delegation/store"
)

// TestCoreOnly_AppliesZeroAGIDMigrations runs ONLY under the core-only build tag
// (trstctl_core). It proves the AGID DDL is not applied without the EE attach: on a
// fresh database a core store with NO extra-migrations seam creates none of the AGID
// tables; registering the seam is what adds them (acceptance criterion 5 / INV-A10 —
// the core-only build applies zero AGID migrations). Building this file requires the
// trstctl_core tag, so it is exercised by `go test -tags trstctl_core`, the same
// build the editions gate links to prove core stays AGID-free.
func TestCoreOnly_AppliesZeroAGIDMigrations(t *testing.T) {
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, testDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer admin.Close(ctx)
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS agid_coreonly")
	if _, err := admin.Exec(ctx, "CREATE DATABASE agid_coreonly"); err != nil {
		t.Fatalf("create db: %v", err)
	}
	dsn := strings.TrimSuffix(testDSN, "/postgres") + "/agid_coreonly"

	// Core store WITHOUT the seam: no AGID tables.
	core, err := corestore.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("core open: %v", err)
	}
	if err := core.Migrate(ctx); err != nil {
		t.Fatalf("core migrate: %v", err)
	}
	for _, tbl := range agidTables {
		if reg := regclass(t, core, tbl); reg != nil {
			t.Fatalf("core-only migrate created an AGID table without the EE attach: %q", *reg)
		}
	}

	// Same database WITH the seam: AGID tables now present.
	seamed, err := corestore.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("seam open: %v", err)
	}
	seamed.WithExtraMigrations(agidstore.MigrationsFS())
	if err := seamed.Migrate(ctx); err != nil {
		t.Fatalf("seam migrate: %v", err)
	}
	for _, tbl := range agidTables {
		if reg := regclass(t, seamed, tbl); reg == nil {
			t.Fatalf("seam did not create the AGID table %q", tbl)
		}
	}
}

// agidTables is every table the AGID DDL creates; the core-only build must create
// none of them.
var agidTables = []string{
	"agent_delegation_records",
	"agent_issuances",
	"agent_attestation_bindings",
	"agent_refusal_records",
	"agent_revocation_directives",
	"agent_revocation_jobs",
	"agent_root_anchors",
}

func regclass(t *testing.T, s *corestore.Store, table string) *string {
	t.Helper()
	var reg *string
	if err := s.SystemPool().QueryRow(context.Background(),
		"SELECT to_regclass('public.'||$1)::text", table).Scan(&reg); err != nil {
		t.Fatalf("to_regclass(%s): %v", table, err)
	}
	return reg
}
