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
//   - RecoveredFromPostgresBackup — independent state not derived from the log
//     (tokens, CA material/state, discovery inventory, attestations, the outbox,
//     idempotency keys, audit checkpoints, …). Recovered from the PostgreSQL dump
//     in the backup set.
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
	"attestations",
	"audit_checkpoints",
	"ca_authorities",
	"ca_ceremony_approvals",
	"ca_crls",
	"ca_issued_certs",
	"ca_key_ceremonies",
	"certificate_profiles",
	"credentials",
	"crypto_assets",
	"ct_log_checkpoints",
	"ct_watched_domains",
	"deployment_targets",
	"idempotency_keys",
	"issuance_approval_requests",
	"issuance_approvals",
	"outbox",
	"policy_bindings",
	"secret_store",
	"ssh_keys",
}

// Ephemeral state is not required for a correct restore (it regenerates).
var Ephemeral = []string{
	"rate_limits",
	// projection_checkpoint is the read-model projection watermark (SPINE-007). On
	// restore the read model is truncated and re-derived by projections.Rebuild,
	// which resets the checkpoint to head — so it is regenerated, never depended on.
	"projection_checkpoint",
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
