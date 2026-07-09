// SPDX-License-Identifier: LicenseRef-trstctl-EE

package store_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/decommission/depstate"
	decstore "trstctl.com/trstctl/ee/decommission/store"
	"trstctl.com/trstctl/internal/eventspec"
	corestore "trstctl.com/trstctl/internal/store"
)

const (
	tenantA = "11111111-1111-1111-1111-111111111111"
	tenantB = "22222222-2222-2222-2222-222222222222"
)

var testDSN string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trstctl-vdec-store-pg")
	if err != nil {
		panic(err)
	}
	port := freePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)).
		RuntimePath(dir + "/rt").
		DataPath(dir + "/data").
		BinariesPath(dir + "/bin").
		Logger(io.Discard).
		StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "embedded postgres start:", err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	testDSN = fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port)
	code := m.Run()
	_ = pg.Stop()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func newRepoOn(t *testing.T, dbName string) *decstore.Repo {
	t.Helper()
	ctx := context.Background()

	admin, err := pgx.Connect(ctx, testDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer admin.Close(ctx)
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{dbName}.Sanitize())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		t.Fatalf("create db %s: %v", dbName, err)
	}
	dsn := strings.TrimSuffix(testDSN, "/postgres") + "/" + dbName

	cs, err := corestore.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("core store open: %v", err)
	}
	cs.WithExtraMigrations(decstore.MigrationsFS())
	if err := cs.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return decstore.New(cs)
}

func mustEncode(t *testing.T, p depstate.Payload, seq uint64) eventspec.Event {
	t.Helper()
	e, err := depstate.Encode(p)
	if err != nil {
		t.Fatalf("Encode(%T): %v", p, err)
	}
	e.Sequence = seq
	return e
}

func dep(class depstate.DependentClass, id string) depstate.Dependent {
	return depstate.Dependent{Class: class, ID: id}
}

func replayEvents(t *testing.T, tenantID string) []eventspec.Event {
	t.Helper()
	return []eventspec.Event{
		mustEncode(t, depstate.DependencyRegisteredV1{TenantID: tenantID, KeyID: "key-a", Dependent: dep(depstate.DependentCiphertext, "ct-1")}, 10),
		mustEncode(t, depstate.DependencyRegisteredV1{TenantID: tenantID, KeyID: "key-a", Dependent: dep(depstate.DependentCredential, "cred-1")}, 11),
		mustEncode(t, depstate.DependencyRegisteredV1{TenantID: tenantID, KeyID: "key-a", Dependent: dep(depstate.DependentWrappedKey, "wrap-1")}, 12),
		mustEncode(t, depstate.DependencyRegisteredV1{TenantID: tenantID, KeyID: "key-a", Dependent: dep(depstate.DependentLeasedSecret, "lease-1")}, 13),
		mustEncode(t, depstate.ReprotectionCompletedV1{TenantID: tenantID, KeyID: "key-a", JobID: "job-ct-1", Dependent: dep(depstate.DependentCiphertext, "ct-1"), SuccessorKeyID: "key-b"}, 14),
		mustEncode(t, depstate.DependencyReleasedV1{TenantID: tenantID, KeyID: "key-a", Dependent: dep(depstate.DependentCredential, "cred-1"), Reason: "expired"}, 15),
		mustEncode(t, depstate.RevocationCompletedV1{TenantID: tenantID, KeyID: "key-a", JobID: "job-lease-1", Dependent: dep(depstate.DependentLeasedSecret, "lease-1"), Destination: "vault/prod"}, 16),
		mustEncode(t, depstate.DependencyErasureDesignatedV1{TenantID: tenantID, KeyID: "key-a", Dependent: dep(depstate.DependentDataSet, "dataset-1"), DesignationRef: "erase/customer-1"}, 17),
	}
}

func TestDepState_DeterministicReplayProjection(t *testing.T) {
	repo := newRepoOn(t, "vdec_det_replay")
	ctx := context.Background()
	events := replayEvents(t, tenantA)

	if err := repo.RebuildTenant(ctx, tenantA, events); err != nil {
		t.Fatalf("rebuild tenant: %v", err)
	}
	expectedProjection, err := depstate.Fold(events)
	if err != nil {
		t.Fatalf("depstate fold: %v", err)
	}
	expected, ok := expectedProjection.Lookup(tenantA, "key-a")
	if !ok {
		t.Fatal("expected projection missing tenant/key")
	}
	got, found, err := repo.FetchKeyState(ctx, tenantA, "key-a")
	if err != nil || !found {
		t.Fatalf("fetch key state: found=%v err=%v", found, err)
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("store projection mismatch:\n got  %#v\n want %#v", got, expected)
	}

	if err := repo.RebuildTenant(ctx, tenantA, events); err != nil {
		t.Fatalf("second rebuild tenant: %v", err)
	}
	gotAgain, found, err := repo.FetchKeyState(ctx, tenantA, "key-a")
	if err != nil || !found {
		t.Fatalf("fetch after second rebuild: found=%v err=%v", found, err)
	}
	if !reflect.DeepEqual(gotAgain, expected) {
		t.Fatalf("second rebuild changed projection:\n got  %#v\n want %#v", gotAgain, expected)
	}
}

func TestRLS_DecommissionStoreCrossTenantDenied(t *testing.T) {
	repo := newRepoOn(t, "vdec_rls")
	ctx := context.Background()
	if err := repo.RebuildTenant(ctx, tenantA, replayEvents(t, tenantA)); err != nil {
		t.Fatalf("rebuild tenantA: %v", err)
	}

	if _, found, err := repo.FetchKeyState(ctx, tenantB, "key-a"); err != nil || found {
		t.Fatalf("tenantB saw tenantA key state: found=%v err=%v", found, err)
	}
	if completions, err := repo.ListCompletionEvents(ctx, tenantB, "key-a"); err != nil || len(completions) != 0 {
		t.Fatalf("tenantB completion events = %d err=%v, want 0 nil", len(completions), err)
	}

	if err := repo.RebuildTenant(ctx, tenantB, replayEvents(t, tenantB)); err != nil {
		t.Fatalf("rebuild tenantB: %v", err)
	}
	gotA, found, err := repo.FetchKeyState(ctx, tenantA, "key-a")
	if err != nil || !found {
		t.Fatalf("tenantA fetch after tenantB write: found=%v err=%v", found, err)
	}
	gotB, found, err := repo.FetchKeyState(ctx, tenantB, "key-a")
	if err != nil || !found {
		t.Fatalf("tenantB own fetch: found=%v err=%v", found, err)
	}
	if gotA.TenantID == gotB.TenantID {
		t.Fatalf("tenant isolation lost: tenantA=%q tenantB=%q", gotA.TenantID, gotB.TenantID)
	}
}

func TestCompletionAndRevocationIndexesSupportGateSets(t *testing.T) {
	repo := newRepoOn(t, "vdec_gate_sets")
	ctx := context.Background()
	if err := repo.RebuildTenant(ctx, tenantA, replayEvents(t, tenantA)); err != nil {
		t.Fatalf("rebuild tenantA: %v", err)
	}

	unaccounted, err := repo.UnaccountedDependents(ctx, tenantA, "key-a")
	if err != nil {
		t.Fatalf("unaccounted dependents: %v", err)
	}
	wantUnaccounted := []depstate.Dependent{dep(depstate.DependentWrappedKey, "wrap-1")}
	if !reflect.DeepEqual(unaccounted, wantUnaccounted) {
		t.Fatalf("unaccounted = %#v, want %#v", unaccounted, wantUnaccounted)
	}

	completions, err := repo.ListCompletionEvents(ctx, tenantA, "key-a")
	if err != nil {
		t.Fatalf("completion events: %v", err)
	}
	if len(completions) != 2 {
		t.Fatalf("completion event count = %d, want 2", len(completions))
	}
	if completions[0].Kind != decstore.CompletionKindReprotection || completions[0].SuccessorKeyID != "key-b" {
		t.Fatalf("first completion = %+v, want reprotection under key-b", completions[0])
	}
	if completions[1].Kind != decstore.CompletionKindRevocation || completions[1].Destination != "vault/prod" {
		t.Fatalf("second completion = %+v, want vault/prod revocation", completions[1])
	}

	revocations, err := repo.ListRevocationCompletions(ctx, tenantA, "key-a")
	if err != nil {
		t.Fatalf("revocation completions: %v", err)
	}
	if len(revocations) != 1 {
		t.Fatalf("revocation completion count = %d, want 1", len(revocations))
	}
	if revocations[0].Destination != "vault/prod" || revocations[0].JobID != "job-lease-1" {
		t.Fatalf("revocation completion = %+v, want vault/prod job-lease-1", revocations[0])
	}
}

func TestCompletionEventsDoNotCollapseSharedJobID(t *testing.T) {
	repo := newRepoOn(t, "vdec_completion_shared_job")
	ctx := context.Background()
	events := []eventspec.Event{
		mustEncode(t, depstate.DependencyRegisteredV1{TenantID: tenantA, KeyID: "key-shared-job", Dependent: dep(depstate.DependentCiphertext, "ct-1")}, 1),
		mustEncode(t, depstate.DependencyRegisteredV1{TenantID: tenantA, KeyID: "key-shared-job", Dependent: dep(depstate.DependentCiphertext, "ct-2")}, 2),
		mustEncode(t, depstate.ReprotectionCompletedV1{TenantID: tenantA, KeyID: "key-shared-job", JobID: "bulk-reprotect", Dependent: dep(depstate.DependentCiphertext, "ct-1"), SuccessorKeyID: "key-b"}, 3),
		mustEncode(t, depstate.ReprotectionCompletedV1{TenantID: tenantA, KeyID: "key-shared-job", JobID: "bulk-reprotect", Dependent: dep(depstate.DependentCiphertext, "ct-2"), SuccessorKeyID: "key-b"}, 4),
	}
	if err := repo.RebuildTenant(ctx, tenantA, events); err != nil {
		t.Fatalf("rebuild tenantA: %v", err)
	}

	completions, err := repo.ListCompletionEvents(ctx, tenantA, "key-shared-job")
	if err != nil {
		t.Fatalf("completion events: %v", err)
	}
	if len(completions) != 2 {
		t.Fatalf("completion event count = %d, want 2 distinct dependents sharing one job id", len(completions))
	}
	gotDependents := []depstate.Dependent{completions[0].Dependent, completions[1].Dependent}
	wantDependents := []depstate.Dependent{dep(depstate.DependentCiphertext, "ct-1"), dep(depstate.DependentCiphertext, "ct-2")}
	if !reflect.DeepEqual(gotDependents, wantDependents) {
		t.Fatalf("completion dependents = %#v, want %#v", gotDependents, wantDependents)
	}
}

func TestCoreOnly_AppliesZeroVDECMigrations(t *testing.T) {
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, testDSN)
	if err != nil {
		t.Fatalf("admin connect: %v", err)
	}
	defer admin.Close(ctx)
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS vdec_coreonly")
	if _, err := admin.Exec(ctx, "CREATE DATABASE vdec_coreonly"); err != nil {
		t.Fatalf("create db: %v", err)
	}
	dsn := strings.TrimSuffix(testDSN, "/postgres") + "/vdec_coreonly"

	core, err := corestore.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("core open: %v", err)
	}
	if err := core.Migrate(ctx); err != nil {
		t.Fatalf("core migrate: %v", err)
	}
	if reg := regclass(t, core, "decommission_key_states"); reg != nil {
		t.Fatalf("core-only migrate created a VDEC table: %q", *reg)
	}

	seamed, err := corestore.Open(ctx, dsn)
	if err != nil {
		t.Fatalf("seam open: %v", err)
	}
	seamed.WithExtraMigrations(decstore.MigrationsFS())
	if err := seamed.Migrate(ctx); err != nil {
		t.Fatalf("seam migrate: %v", err)
	}
	if reg := regclass(t, seamed, "decommission_key_states"); reg == nil {
		t.Fatal("seam did not create the VDEC table")
	}
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
