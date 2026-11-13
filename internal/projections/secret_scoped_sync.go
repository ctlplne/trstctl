// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// Scoped secret sync (A237): a definition, its reviewed applies, and the
// settled deletes of keys it managed.
const (
	EventSecretScopedSyncDefined      = "secret.scoped_sync.defined"       // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	EventSecretScopedSyncRemoved      = "secret.scoped_sync.removed"       // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	EventSecretScopedSyncApplied      = "secret.scoped_sync.applied"       // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	EventSecretScopedSyncKeyDeleted   = "secret.scoped_sync.key_deleted"   // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	EventSecretScopedSyncDeleteFailed = "secret.scoped_sync.delete_failed" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	EventSecretScopedSyncModeSet      = "secret.scoped_sync.mode_set"      // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	EventSecretScopedSyncReconciled   = "secret.scoped_sync.reconciled"    // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
	// EventSecretScopedSyncReplaced replaces a definition in place (A237-L3).
	EventSecretScopedSyncReplaced = "secret.scoped_sync.replaced" // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
)

// SecretScopedSyncDefined is the payload of secret.scoped_sync.defined.
type SecretScopedSyncDefined struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	SourcePrefix      string `json:"source_prefix"`
	Target            string `json:"target"`
	DestinationPrefix string `json:"destination_prefix,omitempty"`
	KeyTransform      string `json:"key_transform"`
	DeleteScope       string `json:"delete_scope"`
	AdoptExisting     bool   `json:"adopt_existing,omitempty"`
	DefinedBy         string `json:"defined_by"`
	// Mode is manual, auto (A237 part b) or approved (A237-L1); absent reads
	// as manual.
	Mode string `json:"mode,omitempty"`
}

// SecretScopedSyncReplaced is the payload of secret.scoped_sync.replaced
// (A237-L3): the definition's new route, rules and mode under the same ID.
// ReleaseKeys says the destination moved (another target, destination prefix
// or key transform), so the keys the definition managed there are released:
// they stay at the destination, as on removal, and the definition no longer
// manages them. The replacer becomes the definition's author.
type SecretScopedSyncReplaced struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	SourcePrefix      string `json:"source_prefix"`
	Target            string `json:"target"`
	DestinationPrefix string `json:"destination_prefix,omitempty"`
	KeyTransform      string `json:"key_transform"`
	DeleteScope       string `json:"delete_scope"`
	AdoptExisting     bool   `json:"adopt_existing,omitempty"`
	Mode              string `json:"mode"`
	ReplacedBy        string `json:"replaced_by"`
	ReleaseKeys       bool   `json:"release_keys,omitempty"`
}

// SecretScopedSyncRemoved is the payload of secret.scoped_sync.removed.
type SecretScopedSyncRemoved struct {
	ID        string `json:"id"`
	RemovedBy string `json:"removed_by"`
}

// SecretScopedSyncAppliedItem is one item of an applied plan.
type SecretScopedSyncAppliedItem struct {
	RemoteKey     string `json:"remote_key"`
	SourceName    string `json:"source_name,omitempty"`
	SourceVersion int    `json:"source_version,omitempty"`
	Action        string `json:"action"`
	JobID         string `json:"job_id,omitempty"`
	DeleteID      string `json:"delete_id,omitempty"`
}

// SecretScopedSyncApplied is the payload of secret.scoped_sync.applied.
type SecretScopedSyncApplied struct {
	TenantEpoch string                        `json:"tenant_epoch"`
	ID          string                        `json:"id"`
	Target      string                        `json:"target"`
	PlanDigest  string                        `json:"plan_digest"`
	AppliedBy   string                        `json:"applied_by"`
	Items       []SecretScopedSyncAppliedItem `json:"items"`
	// Approval is the exact single-use approval an approved-mode definition's
	// plan carries (A237-L1); the projection consumes it with the apply.
	// Absent for manual and auto definitions.
	Approval *store.OperationApprovalUse `json:"approval,omitempty"`
}

// SecretScopedSyncModeSet is the payload of secret.scoped_sync.mode_set.
type SecretScopedSyncModeSet struct {
	ID    string `json:"id"`
	Mode  string `json:"mode"`
	SetBy string `json:"set_by"`
}

// SecretScopedSyncReconciled is the payload of secret.scoped_sync.reconciled:
// what the reconciler last did with an auto definition (applied, unchanged,
// blocked or failed, with a closed-set reason) and the source set it saw.
type SecretScopedSyncReconciled struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	Reason       string `json:"reason,omitempty"`
	PlanDigest   string `json:"plan_digest,omitempty"`
	SourceDigest string `json:"source_digest"`
}

// SecretScopedSyncKeyDeleted is the payload of secret.scoped_sync.key_deleted.
type SecretScopedSyncKeyDeleted struct {
	TenantEpoch string `json:"tenant_epoch"`
	DeleteID    string `json:"delete_id"`
}

// SecretScopedSyncDeleteFailed is the payload of secret.scoped_sync.delete_failed;
// Error is a closed-set reason, never a provider response.
type SecretScopedSyncDeleteFailed struct {
	TenantEpoch string `json:"tenant_epoch"`
	DeleteID    string `json:"delete_id"`
	Error       string `json:"error"`
}

func init() {
	for _, typ := range []string{EventSecretScopedSyncDefined, EventSecretScopedSyncRemoved, EventSecretScopedSyncApplied,
		EventSecretScopedSyncKeyDeleted, EventSecretScopedSyncDeleteFailed, EventSecretScopedSyncModeSet,
		EventSecretScopedSyncReconciled, EventSecretScopedSyncReplaced} {
		knownSchemaVersions[typ] = map[int]bool{1: true}
	}
}

func (p *Projector) applySecretScopedSyncTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	incomplete := func() (bool, error) { return true, fmt.Errorf("projections: %s payload is incomplete", e.Type) }
	switch e.Type {
	case EventSecretScopedSyncDefined:
		var pl SecretScopedSyncDefined
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if pl.ID == "" || pl.Name == "" || pl.SourcePrefix == "" || pl.Target == "" || e.Time.IsZero() {
			return incomplete()
		}
		return true, p.store.ApplySecretScopedSyncDefinedTx(ctx, tx, e.TenantID, store.SecretScopedSync{
			ID: pl.ID, Name: pl.Name, SourcePrefix: pl.SourcePrefix, Target: pl.Target,
			DestinationPrefix: pl.DestinationPrefix, KeyTransform: pl.KeyTransform, DeleteScope: pl.DeleteScope,
			AdoptExisting: pl.AdoptExisting, DefinedBy: pl.DefinedBy, UpdatedAt: e.Time, Mode: pl.Mode,
		}, e.Sequence)
	case EventSecretScopedSyncReplaced:
		var pl SecretScopedSyncReplaced
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if pl.ID == "" || pl.Name == "" || pl.SourcePrefix == "" || pl.Target == "" || pl.Mode == "" || pl.ReplacedBy == "" || e.Time.IsZero() {
			return incomplete()
		}
		return true, p.store.ApplySecretScopedSyncReplacedTx(ctx, tx, e.TenantID, store.SecretScopedSync{
			ID: pl.ID, Name: pl.Name, SourcePrefix: pl.SourcePrefix, Target: pl.Target,
			DestinationPrefix: pl.DestinationPrefix, KeyTransform: pl.KeyTransform, DeleteScope: pl.DeleteScope,
			AdoptExisting: pl.AdoptExisting, DefinedBy: pl.ReplacedBy, UpdatedAt: e.Time, Mode: pl.Mode,
		}, pl.ReleaseKeys, e.Sequence)
	case EventSecretScopedSyncModeSet:
		var pl SecretScopedSyncModeSet
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if pl.ID == "" || (pl.Mode != "manual" && pl.Mode != "auto" && pl.Mode != "approved") || e.Time.IsZero() {
			return incomplete()
		}
		return true, p.store.ApplySecretScopedSyncModeSetTx(ctx, tx, e.TenantID, pl.ID, pl.Mode, e.Time, e.Sequence)
	case EventSecretScopedSyncReconciled:
		var pl SecretScopedSyncReconciled
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if pl.ID == "" || pl.Status == "" || e.Time.IsZero() {
			return incomplete()
		}
		return true, p.store.ApplySecretScopedSyncReconciledTx(ctx, tx, e.TenantID, pl.ID, pl.Status, pl.Reason, pl.SourceDigest, e.Time, e.Sequence)
	case EventSecretScopedSyncRemoved:
		var pl SecretScopedSyncRemoved
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if pl.ID == "" {
			return incomplete()
		}
		return true, p.store.ApplySecretScopedSyncRemovedTx(ctx, tx, e.TenantID, pl.ID)
	case EventSecretScopedSyncApplied:
		var pl SecretScopedSyncApplied
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if pl.ID == "" || pl.TenantEpoch == "" || pl.Target == "" || len(pl.PlanDigest) != 64 || e.Time.IsZero() {
			return incomplete()
		}
		items := make([]store.SecretScopedSyncApplyItem, 0, len(pl.Items))
		for _, item := range pl.Items {
			items = append(items, store.SecretScopedSyncApplyItem{
				RemoteKey: item.RemoteKey, SourceName: item.SourceName, SourceVersion: item.SourceVersion,
				Action: item.Action, JobID: item.JobID, DeleteID: item.DeleteID,
			})
		}
		if err := p.store.ApplySecretScopedSyncAppliedTx(ctx, tx, e.TenantID, pl.TenantEpoch, pl.ID, pl.Target,
			pl.PlanDigest, items, e.Time, e.Sequence); err != nil || pl.Approval == nil {
			return true, err
		}
		// A237-L1: the apply consumes its exact single-use approval; a
		// replay of this event finds it consumed by this same event.
		return true, p.store.ConsumeOperationApprovalTx(ctx, tx, e.TenantID, *pl.Approval, e.ID, e.Time)
	case EventSecretScopedSyncKeyDeleted:
		var pl SecretScopedSyncKeyDeleted
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if pl.DeleteID == "" || e.Time.IsZero() {
			return incomplete()
		}
		return true, p.store.ApplySecretScopedSyncKeyDeletedTx(ctx, tx, e.TenantID, pl.DeleteID, e.Time, e.Sequence)
	case EventSecretScopedSyncDeleteFailed:
		var pl SecretScopedSyncDeleteFailed
		if err := decode(e, &pl); err != nil {
			return true, err
		}
		if pl.DeleteID == "" || pl.Error == "" || e.Time.IsZero() {
			return incomplete()
		}
		return true, p.store.ApplySecretScopedSyncDeleteFailedTx(ctx, tx, e.TenantID, pl.DeleteID, pl.Error, e.Time, e.Sequence)
	default:
		// A238's delivery reports join the same secrets workspace family.
		return p.applySecretDeliveryTx(ctx, tx, e)
	}
}

// addSecretScopedSyncPrivacyPolicies: the actors are identities; the secret
// names — source and destination prefixes, managed keys and their source
// names — are structured paths whose segments an erasure rewrites (A237-L5);
// the definition's name (a slug), targets and digests are opaque.
func addSecretScopedSyncPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	const (
		exact  = events.PrivacyFieldIdentityExact
		opaque = events.PrivacyFieldOpaqueExact
		token  = events.PrivacyFieldSubjectToken
	)
	policies[privacyEventPolicyKey{EventSecretScopedSyncDefined, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/name", opaque), privacyRule("/source_prefix", token),
		privacyRule("/target", opaque), privacyRule("/destination_prefix", token), privacyRule("/key_transform", opaque),
		privacyRule("/delete_scope", opaque), privacyRule("/adopt_existing", opaque), privacyRule("/defined_by", exact),
		privacyRule("/mode", opaque))
	policies[privacyEventPolicyKey{EventSecretScopedSyncReplaced, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/name", opaque), privacyRule("/source_prefix", token),
		privacyRule("/target", opaque), privacyRule("/destination_prefix", token), privacyRule("/key_transform", opaque),
		privacyRule("/delete_scope", opaque), privacyRule("/adopt_existing", opaque), privacyRule("/mode", opaque),
		privacyRule("/replaced_by", exact), privacyRule("/release_keys", opaque))
	policies[privacyEventPolicyKey{EventSecretScopedSyncModeSet, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/mode", opaque), privacyRule("/set_by", exact))
	policies[privacyEventPolicyKey{EventSecretScopedSyncReconciled, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/status", opaque), privacyRule("/reason", opaque),
		privacyRule("/plan_digest", opaque), privacyRule("/source_digest", opaque))
	addSecretDeliveryPrivacyPolicies(policies)
	addSecretMigrationPrivacyPolicies(policies)
	policies[privacyEventPolicyKey{EventSecretScopedSyncRemoved, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/removed_by", exact))
	policies[privacyEventPolicyKey{EventSecretScopedSyncApplied, 1}] = privacyRules(
		privacyRule("/tenant_epoch", opaque), privacyRule("/id", opaque), privacyRule("/target", opaque),
		privacyRule("/plan_digest", opaque), privacyRule("/applied_by", exact),
		privacyRule("/items/*/remote_key", token), privacyRule("/items/*/source_name", token),
		privacyRule("/items/*/source_version", opaque), privacyRule("/items/*/action", opaque),
		privacyRule("/items/*/job_id", opaque), privacyRule("/items/*/delete_id", opaque),
		privacyRule("/approval/request_id", opaque), privacyRule("/approval/intent_digest", opaque),
		privacyRule("/approval/requester", exact), privacyRule("/approval/resource_kind", opaque),
		privacyRule("/approval/resource_id", opaque), privacyRule("/approval/action", opaque),
		privacyRule("/approval/from_state", opaque), privacyRule("/approval/to_state", opaque),
		privacyRule("/approval/target_version", opaque), privacyRule("/approval/required_approvals", opaque),
		privacyRule("/approval/reason", events.PrivacyFieldFreeTextClear),
		privacyRule("/approval/evidence_refs", events.PrivacyFieldFreeTextClear),
		privacyRule("/approval/issuance", opaque))
	policies[privacyEventPolicyKey{EventSecretScopedSyncKeyDeleted, 1}] = privacyRules(
		privacyRule("/tenant_epoch", opaque), privacyRule("/delete_id", opaque))
	policies[privacyEventPolicyKey{EventSecretScopedSyncDeleteFailed, 1}] = privacyRules(
		privacyRule("/tenant_epoch", opaque), privacyRule("/delete_id", opaque), privacyRule("/error", opaque))
}

// addSecretScopedSyncPrivacyShapes registers the scoped sync events' shapes.
func addSecretScopedSyncPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventSecretScopedSyncDefined, 1}] = privacyPayloadShape[SecretScopedSyncDefined]()
	shapes[privacyEventPolicyKey{EventSecretScopedSyncReplaced, 1}] = privacyPayloadShape[SecretScopedSyncReplaced]()
	shapes[privacyEventPolicyKey{EventSecretScopedSyncRemoved, 1}] = privacyPayloadShape[SecretScopedSyncRemoved]()
	shapes[privacyEventPolicyKey{EventSecretScopedSyncApplied, 1}] = privacyPayloadShape[SecretScopedSyncApplied]()
	shapes[privacyEventPolicyKey{EventSecretScopedSyncKeyDeleted, 1}] = privacyPayloadShape[SecretScopedSyncKeyDeleted]()
	shapes[privacyEventPolicyKey{EventSecretScopedSyncDeleteFailed, 1}] = privacyPayloadShape[SecretScopedSyncDeleteFailed]()
	shapes[privacyEventPolicyKey{EventSecretScopedSyncModeSet, 1}] = privacyPayloadShape[SecretScopedSyncModeSet]()
	shapes[privacyEventPolicyKey{EventSecretScopedSyncReconciled, 1}] = privacyPayloadShape[SecretScopedSyncReconciled]()
	addSecretDeliveryPrivacyShapes(shapes)
	addSecretMigrationPrivacyShapes(shapes)
}
