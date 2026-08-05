// SPDX-License-Identifier: MPL-2.0

package backup

import "trstctl.com/trstctl/internal/store"

// The backup-set manifest (SF.4). Disaster recovery is only trustworthy if every
// persistent store is accounted for, so this manifest classifies each PostgreSQL
// table by HOW it is recovered. The manifest test enforces that the classified
// set is exactly the set of tables the migrations create — so a new persistent
// store cannot be added without a deliberate decision about how it is backed up
// and restored. This turns the "any new persistent store joins the backup set"
// convention from prose into an enforced contract.
//
// Recovery classes:
//
//   - RecoveredByLogRebuild — pure projections of the event log (AN-2). The event
//     log is the backup; on restore these are truncated and re-derived by
//     projections.Rebuild. This set must equal store.ReadModelTables (the manifest
//     test asserts it), so a projection table can never drift out of the rebuild.
//   - RecoveredFromPostgresBackup — independent state plus durable receivers whose
//     exact rows are needed during restore preflight (tokens, discovery inventory,
//     attestations, the outbox, idempotency keys, audit checkpoints, …). Recovered
//     from the PostgreSQL dump in the backup set.
//   - Ephemeral — state that is NOT required to recover and regenerates on its own
//     (rate-limit token buckets). Captured incidentally by the PostgreSQL dump but
//     never depended on for a correct restore.

// RecoveredByLogRebuild is the event-sourced read model; the event-log backup +
// projections.Rebuild restores it.
var RecoveredByLogRebuild = append([]string(nil), store.ReadModelTables...)

// RecoveredFromPostgresBackup is independent persistent state restored from the
// PostgreSQL dump in the backup set.
var RecoveredFromPostgresBackup = []string{
	"api_tokens",
	"agent_bootstrap_tokens",
	// A3 credential redemptions. Independent persistent state, not a log
	// projection: nothing in the event log can rebuild WHICH attempt already
	// redeemed, and that fact is the single-use gate itself. Losing it would
	// make every in-flight attempt redeemable a second time after a restore —
	// so it is restored from the PostgreSQL dump like the bootstrap tokens it
	// sits beside, and for the same reason.
	"agent_job_credential_redemptions",
	// A1 signed job receipts. The event log carries every receipt — statement,
	// signature and signer fingerprint travel on agent.job.executed,
	// agent.job.failed and agent.job.receipt.rejected — so in principle this
	// could be rebuilt from a replay. There is no projector that does it: the
	// rows are written by the report handler alongside the event. Classifying
	// it as a log projection would therefore be a claim about a rebuild that
	// does not happen, and the first person to find out would be an operator
	// whose receipt history came back empty after a restore. It is restored
	// from the PostgreSQL dump, honestly, until a projector exists.
	"agent_job_receipts",
	// C3 declared segments. Operator declarations, written directly rather than
	// projected from events, so no replay rebuilds them. Losing them would not
	// corrupt anything — coverage would report "nothing declared", which is the
	// honest zero by design — but it would silently discard real operator work
	// and make an estate look unmeasured rather than unrestored.
	"discovery_segments",
	"attestations",
	// audit_checkpoints is a dual-recovery receiver. The PostgreSQL copy is paired
	// with the event artifact so full restore can prove hidden tenant prefixes are
	// complete before mutation; audit.archived v2 also reconstructs the row during
	// an event-only projection rebuild.
	"audit_checkpoints",
	"credentials",
	"ct_log_checkpoints",
	"ct_watched_domains",
	// Migration 0072 backfilled immutable revisions for deployment targets that
	// predate deployment_target.upserted events. The event log therefore cannot
	// reconstruct the complete target history; both halves restore together from
	// the same PostgreSQL backup cut.
	"deployment_target_revisions",
	"deployment_targets",
	"federation_peer_checkpoints",
	"idempotency_keys",
	"issuance_approval_requests",
	"issuance_approvals",
	"notification_routing_policies",
	"outbox",
	"policy_bindings",
	// This event-populated AN-5 receiver deliberately survives read-model rebuild:
	// a pending raw Idempotency-Key still needs the exact canonical erasure
	// response and request binding even before or independently of projection.
	"privacy_subject_erasure_operations",
	"secret_shares",
	"secret_store",
	"secret_store_versions",
	"ssh_keys",
	// L4: silo placement and residency. RecoveredFromPostgresBackup — it is an
	// operator's placement decision, never derived from the event log, and a
	// rebuild that lost it would silently revert every tenant to the shared
	// default.
	"tenant_silos",
	// L2: provider-plane billing meters. RecoveredFromPostgresBackup, NOT a log
	// projection — usage is counted from live activity, never replayed from the
	// event log, so a rebuild cannot reconstruct it. Losing these to a
	// classification mistake means a provider cannot invoice for the period,
	// and the coverage row is what would have told them the figure was short.
	"provider_usage_meters",
	"provider_usage_coverage",
}

// Ephemeral state is not required for a correct restore (it regenerates).
var Ephemeral = []string{
	"rate_limits",
	// F1 AD CS template posture is an OBSERVATION of an external system, not a
	// fact this system owns. Nothing in the event log can rebuild it, but
	// nothing needs to: a relay re-reads the directory on its next sweep and the
	// row set is replaced wholesale. Restoring a stale copy would be actively
	// worse than an empty page — it would show yesterday's template list as
	// current, and a template someone has since fixed would keep reading
	// dangerous. Empty until the next sweep is the honest post-restore state,
	// and the console's "no relay has read a directory yet" empty state says so
	// rather than implying the estate is clean.
	"adcs_template_posture",
	// projection_checkpoint is the read-model projection watermark (SPINE-007). On
	// restore the read model is truncated and re-derived by projections.Rebuild,
	// which resets the checkpoint to head — so it is regenerated, never depended on.
	"projection_checkpoint",
	// outbox_reconciliation_checkpoint is the boot repair watermark for deriving
	// missing side-effect intents from the event log (SPINE-003). If it is absent or
	// reset on restore, the reconciler simply scans more history; EnqueueIfAbsent
	// keeps already-restored outbox intents idempotent, so correctness does not
	// depend on preserving this cursor.
	"outbox_reconciliation_checkpoint",
	// read_model_snapshots is a boot/DR optimization (EXC-SCALE-01): a periodic
	// snapshot of the read model at an event offset so boot replays only the tail.
	// It is reconstructible by full replay of the event log (the source of truth,
	// AN-2); a missing/corrupt snapshot degrades to a full Rebuild, never data loss —
	// so it is not required for a correct restore.
	"read_model_snapshots",
}

// RecoveryClass names how a table is recovered in a disaster.
type RecoveryClass string

const (
	ClassLogRebuild     RecoveryClass = "recovered-by-log-rebuild"
	ClassPostgresBackup RecoveryClass = "recovered-from-postgres-backup"
	ClassEphemeral      RecoveryClass = "ephemeral"
)

// Classify returns the recovery class of a table and whether it is in the
// manifest at all. A persistent table that is not classified is a disaster-
// recovery gap — the manifest test fails on it.
func Classify(table string) (RecoveryClass, bool) {
	for _, t := range RecoveredByLogRebuild {
		if t == table {
			return ClassLogRebuild, true
		}
	}
	for _, t := range RecoveredFromPostgresBackup {
		if t == table {
			return ClassPostgresBackup, true
		}
	}
	for _, t := range Ephemeral {
		if t == table {
			return ClassEphemeral, true
		}
	}
	return "", false
}
