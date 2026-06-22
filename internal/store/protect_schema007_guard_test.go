package store

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
)

// SCHEMA-007 (16-SCHEMA) PROTECT regression guard.
//
// Confirmed strength: schema migrations are ORDERED, LEDGERED (schema_migrations),
// ADVISORY-LOCK SERIALIZED (only one instance migrates at a time), FORWARD-ONLY, and
// ONLINE-SAFE (no-transaction migrations may run CREATE INDEX CONCURRENTLY while the
// run is still serialized). Anchor: internal/store/migrate.go
// (MigrateAdvisoryLockKey, the schema_migrations ledger, sorted apply, recorded
// versions, try-lock probes, no-transaction opt-in).
//
// PG-FREE by design. Two parts: (1) a BEHAVIORAL check on the real embedded migration
// set via the in-package helpers migrationNames()/versionOf() — the list is sorted by
// version, the versions are contiguous (no gaps, no duplicates) and forward-only from
// 1; (2) an ANCHOR-LOCK over migrate.go for the advisory-lock + ledger + sorted-apply
// machinery. It NEVER starts Postgres. If a migration is added out of order, a gap or
// duplicate appears, or the advisory-lock/ledger serialization is removed, this guard
// goes RED.

func TestProtectSCHEMA007_MigrationsOrderedContiguousForwardOnly(t *testing.T) {
	names, err := migrationNames()
	if err != nil {
		t.Fatalf("SCHEMA-007: migrationNames() failed reading the embedded migrations: %v", err)
	}
	if len(names) == 0 {
		t.Fatal("SCHEMA-007: no embedded migrations found; the ordered, ledgered migration set is the schema's source of truth and must be non-empty")
	}

	// migrationNames() must return them already sorted (Migrate applies in this order).
	if !sort.StringsAreSorted(names) {
		t.Errorf("SCHEMA-007: migrationNames() is not lexically sorted: %v; migrations must apply in a deterministic order", names)
	}

	// Versions must be contiguous and strictly increasing from 1 (forward-only, no
	// gaps, no duplicates) so the ledger and the embedded set stay in lockstep.
	var prev int64
	for i, name := range names {
		v, verr := versionOf(name)
		if verr != nil {
			t.Fatalf("SCHEMA-007: migration %q has an unparseable version: %v", name, verr)
		}
		want := int64(i + 1)
		if v != want {
			t.Fatalf("SCHEMA-007: migration #%d is version %d (%q), want %d — versions must be contiguous and forward-only (no gaps, no reordering)", i+1, v, name, want)
		}
		if i > 0 && v <= prev {
			t.Fatalf("SCHEMA-007: migration versions are not strictly increasing at %q (%d after %d); forward-only ordering broken", name, v, prev)
		}
		prev = v
	}
}

func TestProtectSCHEMA007_AdvisoryLockAndLedgerAnchor(t *testing.T) {
	// MigrateAdvisoryLockKey is the exported, fixed serialization key; assert it is
	// the documented "ctlmgr" constant and stays non-zero so concurrent instances
	// genuinely contend on the same lock.
	if MigrateAdvisoryLockKey == 0 {
		t.Fatal("SCHEMA-007: MigrateAdvisoryLockKey is 0; migration runs would not serialize on a shared advisory lock")
	}
	if MigrateAdvisoryLockKey != 0x63746C6D6772 {
		t.Errorf("SCHEMA-007: MigrateAdvisoryLockKey = %#x, want 0x63746C6D6772 (\"ctlmgr\"); a change here breaks cross-instance migration serialization", MigrateAdvisoryLockKey)
	}

	src, err := os.ReadFile("migrate.go")
	if err != nil {
		t.Fatalf("SCHEMA-007 anchor: cannot read migrate.go: %v", err)
	}
	body := string(src)
	for _, needle := range []string{
		"MigrateAdvisoryLockKey",        // the run is serialized on this key
		"pg_try_advisory_lock",          // try-lock probes (online-DDL-safe serialization)
		"pg_advisory_unlock",            // the lock is released after the run
		"schema_migrations",             // the forward-only ledger
		"INSERT INTO schema_migrations", // each applied migration is recorded
		"sort.Strings(names)",           // migrations applied in sorted (version) order
		"migrate: no-transaction",       // online-safe opt-out for CREATE INDEX CONCURRENTLY
		"if applied[version]",           // already-applied migrations are skipped (forward-only)
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("SCHEMA-007: migrate.go no longer contains %q; the ordered/ledgered/advisory-lock-serialized/forward-only migration machinery may have regressed", needle)
		}
	}

	// Lock the ordering: the run must take the advisory lock BEFORE it creates the
	// ledger and applies migrations (so two instances cannot both create+apply).
	lockIdx := strings.Index(body, "acquireMigrationLock(")
	ledgerIdx := strings.Index(body, "CREATE TABLE IF NOT EXISTS schema_migrations")
	if lockIdx < 0 || ledgerIdx < 0 {
		t.Fatalf("SCHEMA-007: migrate.go no longer acquires the migration lock before creating the ledger; re-validate the serialization order")
	}
	if !(lockIdx < ledgerIdx) {
		t.Errorf("SCHEMA-007: the advisory lock (@%d) is no longer taken before the ledger is created (@%d); concurrent instances could race the migration run", lockIdx, ledgerIdx)
	}
}

// PKIGOV-005 (19-PKIGOV) PROTECT regression guard.
//
// Confirmed strength: CA key-ceremony approvals are DISTINCT (one per custodian),
// EVIDENCE-BACKED (a row counts toward quorum only once it is bound to an immutable
// event id + stream sequence), TENANT-SCOPED (every query runs under WithTenant / RLS,
// AN-1), PURPOSE-BOUND (a ceremony is consumed only for its expected purpose), and
// SIGNED/SEPARATED (an anonymous custodian and a self-approval by the opener are both
// rejected — opener != approver). Anchor: internal/store/ca.go.
//
// PG-FREE. Part 1 BEHAVIORAL: ReserveKeyCeremonyApproval and
// AttachKeyCeremonyApprovalEvidence reject before touching the database when their
// inputs cannot possibly be valid — an empty custodian yields ErrAnonymousApproval, and
// missing evidence (empty event id / zero sequence) yields an error — so we exercise the
// real exported guards without a live store. Part 2 ANCHOR-LOCK: ca.go still contains
// the self-approval, evidence-only-quorum, purpose-match, and tenant-scoping logic. If a
// future edit lets an anonymous/self approval through, or counts un-evidenced rows toward
// quorum, this guard goes RED.
func TestProtectPKIGOV005_AnonymousAndUnevidencedApprovalsRejected(t *testing.T) {
	s := &Store{} // no pool needed: these guards reject before any DB access.

	// An anonymous (empty) custodian is rejected up front — a custodian must be a
	// named, authenticated principal. This returns before WithTenant touches the pool.
	if _, _, err := s.ReserveKeyCeremonyApproval(context.Background(), "tenant-1", "ceremony-1", ""); err != ErrAnonymousApproval {
		t.Fatalf("PKIGOV-005: ReserveKeyCeremonyApproval with an empty custodian = %v, want ErrAnonymousApproval (anonymous approvals must be rejected)", err)
	}

	// Evidence is mandatory for quorum power: a missing event id or zero sequence is
	// rejected before any DB write, so an un-evidenced row can never gain quorum power.
	if _, err := s.AttachKeyCeremonyApprovalEvidence(context.Background(), "tenant-1", "ceremony-1", "custodian-a", "", 1); err == nil {
		t.Fatalf("PKIGOV-005: AttachKeyCeremonyApprovalEvidence accepted an empty event id; quorum evidence must be required")
	}
	if _, err := s.AttachKeyCeremonyApprovalEvidence(context.Background(), "tenant-1", "ceremony-1", "custodian-a", "evt-1", 0); err == nil {
		t.Fatalf("PKIGOV-005: AttachKeyCeremonyApprovalEvidence accepted a zero stream sequence; quorum evidence must be required")
	}
}

func TestProtectPKIGOV005_CeremonyGovernanceAnchor(t *testing.T) {
	// The distinct named sentinels for the separation-of-duties / evidence rules must
	// remain present.
	if ErrSelfApproval == nil || ErrAnonymousApproval == nil || ErrKeyCeremonyQuorumNotMet == nil || ErrKeyCeremonyPurposeMismatch == nil {
		t.Fatal("PKIGOV-005: a ceremony-governance error sentinel is nil; the distinct rejection reasons must exist")
	}

	src, err := os.ReadFile("ca.go")
	if err != nil {
		t.Fatalf("PKIGOV-005 anchor: cannot read ca.go: %v", err)
	}
	body := string(src)
	for _, needle := range []string{
		"if custodian == \"\" {",                // anonymous approval rejected
		"return 0, false, ErrAnonymousApproval", // ...with the distinct sentinel
		"opener != \"\" && opener == custodian", // self-approval (opener == approver) check
		"return ErrSelfApproval",                // ...rejected with the distinct sentinel
		"approval_event_id IS NOT NULL",         // only evidence-backed rows count toward quorum
		"c.Approvals < c.Threshold",             // quorum threshold enforced on consume
		"ErrKeyCeremonyQuorumNotMet",            // ...with the distinct sentinel
		"c.Purpose != expectedPurpose",          // purpose-bound consume
		"ErrKeyCeremonyPurposeMismatch",         // ...with the distinct sentinel
		"s.WithTenant(ctx",                      // tenant-scoped (AN-1 / RLS)
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("PKIGOV-005: ca.go no longer contains %q; the distinct/evidence-backed/tenant-scoped/purpose-bound/separated approval machinery may have regressed", needle)
		}
	}

	// Lock that quorum is counted ONLY over evidence-backed rows: the count query must
	// filter on approval_event_id IS NOT NULL. Assert the count appears alongside that
	// filter (rather than a bare count of all approval rows).
	countWithEvidence := strings.Contains(body, "SELECT count(*) FROM ca_ceremony_approvals") &&
		strings.Contains(body, "AND approval_event_id IS NOT NULL")
	if !countWithEvidence {
		t.Error("PKIGOV-005: the approval quorum count no longer filters on approval_event_id IS NOT NULL; un-evidenced reservations could gain quorum power")
	}
}
