// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/secretmigrate"
	"trstctl.com/trstctl/internal/store"
)

// Secret migrations (A243). No event carries a value: a run's plan is the
// value-free assessment, and every version it writes travels in the
// versioned-batch event like any other secret write.
const (
	EventSecretMigrationAssessed           = "secret.migration.assessed"            // #nosec G101 -- event type name, no credential (CWE-798)
	EventSecretMigrationStaged             = "secret.migration.staged"              // #nosec G101 -- event type name, no credential (CWE-798)
	EventSecretMigrationPermissionsApplied = "secret.migration.permissions_applied" // #nosec G101 -- event type name, no credential (CWE-798)
	EventSecretMigrationConsumerRead       = "secret.migration.consumer_read"       // #nosec G101 -- event type name, no credential (CWE-798)
	EventSecretMigrationCutOver            = "secret.migration.cut_over"            // #nosec G101 -- event type name, no credential (CWE-798)
	EventSecretMigrationReissued           = "secret.migration.reissued"            // #nosec G101 -- event type name, no credential (CWE-798)
	EventSecretMigrationRolledBack         = "secret.migration.rolled_back"         // #nosec G101 -- event type name, no credential (CWE-798)
)

// SecretMigrationAssessed is a run's (re)assessment: the value-free plan, the
// digest that binds it to the values it was made from, and the open
// environments the operator accepted.
type SecretMigrationAssessed struct {
	ID           string                   `json:"id"`
	Project      string                   `json:"project"`
	Digest       string                   `json:"digest"`
	Plan         secretmigrate.Assessment `json:"plan"`
	AcceptedOpen []string                 `json:"accepted_open"`
	By           string                   `json:"by"`
}

// SecretMigrationVersion is one object a migration wrote: the version it found
// (0: none) and the version it wrote.
type SecretMigrationVersion struct {
	Name         string `json:"name"`
	PriorVersion int    `json:"prior_version"`
	Version      int    `json:"version"`
}

// SecretMigrationStaged records an import of a run's values as new versions,
// the export's system staying each secret's writer.
type SecretMigrationStaged struct {
	ID      string                   `json:"id"`
	BatchID string                   `json:"batch_id"`
	Items   []SecretMigrationVersion `json:"items"`
	By      string                   `json:"by"`
}

// SecretMigrationGrant is one membership a run applied.
type SecretMigrationGrant struct {
	Subject      string   `json:"subject"`
	Role         string   `json:"role"`
	Environments []string `json:"environments"`
}

// SecretMigrationPermissionsApplied records the translated grants applied.
type SecretMigrationPermissionsApplied struct {
	ID     string                 `json:"id"`
	Grants []SecretMigrationGrant `json:"grants"`
	By     string                 `json:"by"`
}

// SecretMigrationConsumerRead is a consumer's first read of a migrated secret
// from the store, as its own subject.
type SecretMigrationConsumerRead struct {
	ID       string `json:"id"`
	Consumer string `json:"consumer"`
	Name     string `json:"name"`
	Version  int    `json:"version"`
	Reader   string `json:"reader"`
}

// SecretMigrationCutOver hands each staged secret's writing to the store.
type SecretMigrationCutOver struct {
	ID string `json:"id"`
	By string `json:"by"`
}

// SecretMigrationReissued records credentials the export could not carry,
// issued anew in the store: never counted as migrated.
type SecretMigrationReissued struct {
	ID      string                   `json:"id"`
	BatchID string                   `json:"batch_id"`
	Items   []SecretMigrationVersion `json:"items"`
	By      string                   `json:"by"`
}

// SecretMigrationRollbackItem is one object's rollback: restored to its prior
// version (as a new version), deleted (it did not exist before), or kept (it
// changed after the migration wrote it).
type SecretMigrationRollbackItem struct {
	Name     string `json:"name"`
	Rollback string `json:"rollback"`
	Version  int    `json:"version"`
}

// SecretMigrationRolledBack records a run's rollback from its manifest.
type SecretMigrationRolledBack struct {
	ID    string                        `json:"id"`
	Items []SecretMigrationRollbackItem `json:"items"`
	By    string                        `json:"by"`
}

func init() {
	for _, t := range []string{EventSecretMigrationAssessed, EventSecretMigrationStaged, EventSecretMigrationPermissionsApplied,
		EventSecretMigrationConsumerRead, EventSecretMigrationCutOver, EventSecretMigrationReissued, EventSecretMigrationRolledBack} {
		knownSchemaVersions[t] = map[int]bool{1: true}
	}
}

func (p *Projector) applySecretMigrationTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	if e.Time.IsZero() {
		switch e.Type {
		case EventSecretMigrationAssessed, EventSecretMigrationStaged, EventSecretMigrationPermissionsApplied,
			EventSecretMigrationConsumerRead, EventSecretMigrationCutOver, EventSecretMigrationReissued, EventSecretMigrationRolledBack:
			return true, fmt.Errorf("projections: %s has no time", e.Type)
		}
	}
	switch e.Type {
	case EventSecretMigrationAssessed:
		var pl SecretMigrationAssessed
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		plan, err := json.Marshal(pl.Plan)
		if err != nil {
			return true, err
		}
		return true, p.store.ApplySecretMigrationAssessedTx(ctx, tx, store.SecretMigration{
			TenantID: e.TenantID, ID: pl.ID, Project: pl.Project, Digest: pl.Digest, Plan: plan,
			AcceptedOpen: pl.AcceptedOpen, CreatedBy: pl.By, CreatedAt: e.Time,
		}, e.Sequence)
	case EventSecretMigrationStaged, EventSecretMigrationReissued:
		var pl SecretMigrationStaged
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		outcome := store.SecretMigrationMigrated
		if e.Type == EventSecretMigrationReissued {
			outcome = store.SecretMigrationReissued
		}
		items := make([]store.SecretMigrationObject, 0, len(pl.Items))
		for _, item := range pl.Items {
			items = append(items, store.SecretMigrationObject{Name: item.Name, PriorVersion: item.PriorVersion, Version: item.Version, Outcome: outcome})
		}
		return true, p.store.ApplySecretMigrationWrittenTx(ctx, tx, e.TenantID, pl.ID, outcome, items, pl.By, e.Time, e.Sequence)
	case EventSecretMigrationPermissionsApplied:
		var pl SecretMigrationPermissionsApplied
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		grants, err := json.Marshal(pl.Grants)
		if err != nil {
			return true, err
		}
		return true, p.store.ApplySecretMigrationPermissionsAppliedTx(ctx, tx, e.TenantID, pl.ID, grants, e.Time, e.Sequence)
	case EventSecretMigrationConsumerRead:
		var pl SecretMigrationConsumerRead
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		return true, p.store.ApplySecretMigrationConsumerReadTx(ctx, tx, e.TenantID, store.SecretMigrationConsumerRead{
			MigrationID: pl.ID, Consumer: pl.Consumer, Name: pl.Name, Version: pl.Version, Reader: pl.Reader, ReadAt: e.Time,
		}, e.Sequence)
	case EventSecretMigrationCutOver:
		var pl SecretMigrationCutOver
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		return true, p.store.ApplySecretMigrationCutOverTx(ctx, tx, e.TenantID, pl.ID, pl.By, e.Time, e.Sequence)
	case EventSecretMigrationRolledBack:
		var pl SecretMigrationRolledBack
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		items := make([]store.SecretMigrationObject, 0, len(pl.Items))
		for _, item := range pl.Items {
			items = append(items, store.SecretMigrationObject{Name: item.Name, Rollback: item.Rollback, RollbackVersion: item.Version})
		}
		return true, p.store.ApplySecretMigrationRolledBackTx(ctx, tx, e.TenantID, pl.ID, items, pl.By, e.Time, e.Sequence)
	default:
		return false, nil
	}
}

// addSecretMigrationPrivacyPolicies: subjects and the actor are identities;
// owners, descriptions and reasons are free text cleared when they contain
// an erased subject; names, versions, digests and enums are opaque.
func addSecretMigrationPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	const (
		identity = events.PrivacyFieldIdentityExact
		text     = events.PrivacyFieldFreeTextClear
		opaque   = events.PrivacyFieldOpaqueExact
	)
	plan := []events.PrivacyFieldRule{
		privacyRule("/id", opaque), privacyRule("/project", opaque), privacyRule("/digest", opaque),
		privacyRule("/accepted_open/*", opaque), privacyRule("/by", identity),
		privacyRule("/plan/project", opaque),
		privacyRule("/plan/environments/*/name", opaque), privacyRule("/plan/environments/*/objects", opaque),
		privacyRule("/plan/environments/*/folders/*", opaque), privacyRule("/plan/environments/*/exists", opaque),
		privacyRule("/plan/environments/*/restricted", opaque), privacyRule("/plan/environments/*/source_restricted", opaque),
		privacyRule("/plan/environments/*/open", opaque), privacyRule("/plan/environments/*/open_accepted", opaque),
		privacyRule("/plan/objects/*/name", opaque), privacyRule("/plan/objects/*/environment", opaque),
		privacyRule("/plan/objects/*/folder", opaque), privacyRule("/plan/objects/*/key", opaque),
		privacyRule("/plan/objects/*/action", opaque), privacyRule("/plan/objects/*/reason", text),
		privacyRule("/plan/objects/*/existing_version", opaque), privacyRule("/plan/objects/*/multiline", opaque),
		privacyRule("/plan/objects/*/description", text), privacyRule("/plan/objects/*/tags/*", text),
		privacyRule("/plan/objects/*/owner", text), privacyRule("/plan/objects/*/references/*", opaque),
		privacyRule("/plan/objects/*/location", opaque),
		privacyRule("/plan/unsupported/*/location", opaque), privacyRule("/plan/unsupported/*/reason", text),
		privacyRule("/plan/permissions/*/subject", identity), privacyRule("/plan/permissions/*/access", opaque),
		privacyRule("/plan/permissions/*/environment", opaque), privacyRule("/plan/permissions/*/folder", opaque),
		privacyRule("/plan/permissions/*/status", opaque), privacyRule("/plan/permissions/*/role", opaque),
		privacyRule("/plan/permissions/*/environments/*", opaque), privacyRule("/plan/permissions/*/reason", text),
		privacyRule("/plan/consumers/*/name", opaque), privacyRule("/plan/consumers/*/subject", identity),
		privacyRule("/plan/consumers/*/environment", opaque), privacyRule("/plan/consumers/*/secrets/*", opaque),
		privacyRule("/plan/consumers/*/problem", text),
		privacyRule("/plan/counts/import", opaque), privacyRule("/plan/counts/reissue", opaque),
		privacyRule("/plan/counts/blocked", opaque), privacyRule("/plan/counts/unsupported", opaque),
		privacyRule("/plan/counts/permissions_translated", opaque), privacyRule("/plan/counts/permissions_held", opaque),
	}
	versions := []events.PrivacyFieldRule{
		privacyRule("/id", opaque), privacyRule("/batch_id", opaque), privacyRule("/by", identity),
		privacyRule("/items/*/name", opaque), privacyRule("/items/*/prior_version", opaque), privacyRule("/items/*/version", opaque),
	}
	policies[privacyEventPolicyKey{EventSecretMigrationAssessed, 1}] = privacyRules(plan...)
	policies[privacyEventPolicyKey{EventSecretMigrationStaged, 1}] = privacyRules(versions...)
	policies[privacyEventPolicyKey{EventSecretMigrationReissued, 1}] = privacyRules(versions...)
	policies[privacyEventPolicyKey{EventSecretMigrationPermissionsApplied, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/by", identity), privacyRule("/grants/*/subject", identity),
		privacyRule("/grants/*/role", opaque), privacyRule("/grants/*/environments/*", opaque))
	policies[privacyEventPolicyKey{EventSecretMigrationConsumerRead, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/consumer", opaque), privacyRule("/name", opaque),
		privacyRule("/version", opaque), privacyRule("/reader", identity))
	policies[privacyEventPolicyKey{EventSecretMigrationCutOver, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/by", identity))
	policies[privacyEventPolicyKey{EventSecretMigrationRolledBack, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/by", identity), privacyRule("/items/*/name", opaque),
		privacyRule("/items/*/rollback", opaque), privacyRule("/items/*/version", opaque))
}

func addSecretMigrationPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventSecretMigrationAssessed, 1}] = privacyPayloadShape[SecretMigrationAssessed]()
	shapes[privacyEventPolicyKey{EventSecretMigrationStaged, 1}] = privacyPayloadShape[SecretMigrationStaged]()
	shapes[privacyEventPolicyKey{EventSecretMigrationReissued, 1}] = privacyPayloadShape[SecretMigrationReissued]()
	shapes[privacyEventPolicyKey{EventSecretMigrationPermissionsApplied, 1}] = privacyPayloadShape[SecretMigrationPermissionsApplied]()
	shapes[privacyEventPolicyKey{EventSecretMigrationConsumerRead, 1}] = privacyPayloadShape[SecretMigrationConsumerRead]()
	shapes[privacyEventPolicyKey{EventSecretMigrationCutOver, 1}] = privacyPayloadShape[SecretMigrationCutOver]()
	shapes[privacyEventPolicyKey{EventSecretMigrationRolledBack, 1}] = privacyPayloadShape[SecretMigrationRolledBack]()
}
