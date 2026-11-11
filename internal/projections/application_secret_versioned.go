// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// EventApplicationSecretBatchVersioned is one environment promotion or folder
// restore (A236): new versions of several secrets as one indivisible command.
const EventApplicationSecretBatchVersioned = "secret.batch_versioned"
const ApplicationSecretBatchVersionSchemaVersion = 1
const ApplicationSecretBatchVersionPrivacyTombstoneSchemaVersion = 2

// ApplicationSecretBatchVersionItem is one secret of a versioned batch. Sealed
// is bound to Name as AAD. SourceName/SourceVersion say where the value came
// from: the promoted secret, or the restored version of the same name.
type ApplicationSecretBatchVersionItem struct {
	Name            string `json:"name"`
	ExpectedVersion int    `json:"expected_version"`
	ResultVersion   int    `json:"result_version"`
	Sealed          []byte `json:"sealed"`
	SourceName      string `json:"source_name"`
	SourceVersion   int    `json:"source_version"`
	// OwnerID is the owner a promotion's newly created secret takes from its
	// source (A236-L2); absent on an update, a restore, a migration, and a
	// batch recorded before it was carried.
	OwnerID string `json:"owner_id,omitempty"`
}

// ApplicationSecretBatchVersion carries no plaintext and no raw
// Idempotency-Key; PlanDigest is the reviewed plan it executes.
type ApplicationSecretBatchVersion struct {
	TenantEpoch          string                              `json:"tenant_epoch"`
	IdempotencyKeyDigest string                              `json:"idempotency_key_sha256"`
	RequestBinding       string                              `json:"request_binding_hmac_sha256"`
	CommandEvidence      string                              `json:"command_evidence"`
	Surface              string                              `json:"surface"`
	Operation            string                              `json:"operation"`
	PlanDigest           string                              `json:"plan_digest"`
	Items                []ApplicationSecretBatchVersionItem `json:"items"`
	// Approval is the exact single-use approval a promotion into a restricted
	// environment carries (A236-L1); the projection consumes it with the
	// versions it writes. Absent on every other batch.
	Approval *store.OperationApprovalUse `json:"approval,omitempty"`
}

// ApplicationSecretBatchVersionPrivacyPruned is the privacy rewrite: items whose
// name holds an erased subject are removed, like a pruned batch import.
type ApplicationSecretBatchVersionPrivacyPruned struct {
	ApplicationSecretBatchVersion
	PrivacyDisposition         string `json:"privacy_disposition"`
	PrivacySubjectRef          string `json:"privacy_subject_ref"`
	PrivacySourceSchemaVersion int    `json:"privacy_source_schema_version"`
	PrivacyRemovedCount        int    `json:"privacy_removed_count"`
}

func init() {
	knownSchemaVersions[EventApplicationSecretBatchVersioned] = map[int]bool{
		ApplicationSecretBatchVersionSchemaVersion:                 true,
		ApplicationSecretBatchVersionPrivacyTombstoneSchemaVersion: true,
	}
	rules := []events.PrivacyFieldRule{
		{Path: "/tenant_epoch", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/idempotency_key_sha256", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/request_binding_hmac_sha256", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/command_evidence", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/surface", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/operation", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/plan_digest", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/items/*/name", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/items/*/expected_version", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/items/*/result_version", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/items/*/sealed", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/items/*/source_name", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/items/*/source_version", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/items/*/owner_id", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/request_id", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/intent_digest", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/requester", Mode: events.PrivacyFieldIdentityExact},
		{Path: "/approval/resource_kind", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/resource_id", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/action", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/from_state", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/to_state", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/target_version", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/required_approvals", Mode: events.PrivacyFieldOpaqueExact},
		{Path: "/approval/reason", Mode: events.PrivacyFieldFreeTextClear},
		{Path: "/approval/evidence_refs", Mode: events.PrivacyFieldFreeTextClear},
		{Path: "/approval/issuance", Mode: events.PrivacyFieldOpaqueExact},
	}
	if err := events.RegisterPrivacyEventPolicy(EventApplicationSecretBatchVersioned,
		ApplicationSecretBatchVersionSchemaVersion, events.PrivacyEventPolicy{
			Rules:        rules,
			PayloadShape: events.PrivacyPayloadShapeOf[ApplicationSecretBatchVersion](),
		}); err != nil {
		panic(err)
	}
	pruned := append(slices.Clone(rules),
		events.PrivacyFieldRule{Path: "/privacy_disposition", Mode: events.PrivacyFieldOpaqueExact},
		events.PrivacyFieldRule{Path: "/privacy_subject_ref", Mode: events.PrivacyFieldOpaqueExact},
		events.PrivacyFieldRule{Path: "/privacy_source_schema_version", Mode: events.PrivacyFieldOpaqueExact},
		events.PrivacyFieldRule{Path: "/privacy_removed_count", Mode: events.PrivacyFieldOpaqueExact},
	)
	if err := events.RegisterPrivacyEventPolicy(EventApplicationSecretBatchVersioned,
		ApplicationSecretBatchVersionPrivacyTombstoneSchemaVersion, events.PrivacyEventPolicy{
			Rules:        pruned,
			PayloadShape: events.PrivacyPayloadShapeOf[ApplicationSecretBatchVersionPrivacyPruned](),
		}); err != nil {
		panic(err)
	}
}

func (p *Projector) applyApplicationSecretBatchVersionTx(ctx context.Context, tx pgx.Tx, event events.Event) (bool, error) {
	if event.Type != EventApplicationSecretBatchVersioned {
		return false, nil
	}
	privacyPruned := schemaVersionOf(event) == ApplicationSecretBatchVersionPrivacyTombstoneSchemaVersion
	var payload ApplicationSecretBatchVersion
	if privacyPruned {
		var pruned ApplicationSecretBatchVersionPrivacyPruned
		if err := decode(event, &pruned); err != nil {
			return true, err
		}
		if pruned.PrivacyDisposition != "name_items_pruned" ||
			!store.IsPrivacyReference(pruned.PrivacySubjectRef) ||
			pruned.PrivacySourceSchemaVersion != ApplicationSecretBatchVersionSchemaVersion ||
			pruned.PrivacyRemovedCount < 1 || pruned.PrivacyRemovedCount+len(pruned.Items) > 100 {
			return true, errors.New("projections: invalid versioned batch privacy disposition")
		}
		payload = pruned.ApplicationSecretBatchVersion
	} else if err := decode(event, &payload); err != nil {
		return true, err
	}
	if (!privacyPruned && len(payload.Items) == 0) || len(payload.Items) > 100 ||
		len(payload.RequestBinding) != 64 || len(payload.IdempotencyKeyDigest) != 64 ||
		len(payload.CommandEvidence) != 64 || len(payload.PlanDigest) != 64 || payload.Surface != "native" ||
		payload.TenantEpoch == "" ||
		(payload.Operation != store.ApplicationSecretBatchPromotion && payload.Operation != store.ApplicationSecretBatchRestore &&
			payload.Operation != store.ApplicationSecretBatchMigration) {
		return true, errors.New("projections: incomplete versioned secret batch")
	}
	if privacyPruned && len(payload.Items) == 0 {
		return true, nil
	}
	names := make([]string, 0, len(payload.Items))
	items := make([]store.ApplicationSecretVersionItem, 0, len(payload.Items))
	for _, item := range payload.Items {
		if item.Name == "" || len(item.Sealed) == 0 || item.ExpectedVersion < 0 ||
			item.ResultVersion != item.ExpectedVersion+1 || item.SourceName == "" || item.SourceVersion < 1 {
			return true, errors.New("projections: invalid versioned secret batch item")
		}
		if item.OwnerID != "" && (item.ExpectedVersion != 0 || payload.Operation != store.ApplicationSecretBatchPromotion ||
			uuid.Validate(item.OwnerID) != nil) {
			return true, errors.New("projections: only a promotion's created secret takes an owner")
		}
		var recovered *int
		if payload.Operation == store.ApplicationSecretBatchRestore {
			if item.SourceName != item.Name {
				return true, errors.New("projections: a restore item restores another name")
			}
			source := item.SourceVersion
			recovered = &source
		}
		names = append(names, item.Name)
		items = append(items, store.ApplicationSecretVersionItem{
			Name: item.Name, ExpectedVersion: item.ExpectedVersion, ResultVersion: item.ResultVersion,
			Sealed: item.Sealed, RecoveredFrom: recovered, OwnerID: item.OwnerID,
		})
	}
	if !slices.IsSorted(names) {
		return true, errors.New("projections: versioned secret batch names are not sorted")
	}
	for index := 1; index < len(names); index++ {
		if names[index] == names[index-1] {
			return true, errors.New("projections: duplicate versioned secret batch name")
		}
	}
	semantic := crypto.SHA256Hex([]byte(fmt.Sprintf("trstctl.secret.batch-versioned.v1\x00%s\x00%s\x00%s\x00%d\x00%s",
		event.ID, event.TenantID, event.Time.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		schemaVersionOf(event), event.Data)))
	err := p.store.ApplyApplicationSecretVersionBatchTx(ctx, tx, store.ApplicationSecretImportBatch{
		TenantID: event.TenantID, EventID: event.ID, TenantEpoch: payload.TenantEpoch,
		RequestBinding: payload.RequestBinding, Payload: event.Data,
		PayloadDigest: crypto.SHA256Hex(event.Data), Actor: event.Actor,
		EventTime: event.Time, Names: names, Operation: payload.Operation,
	}, semantic, items, privacyPruned)
	if errors.Is(err, store.ErrApplicationSecretTenantEpochMismatch) {
		return true, nil
	}
	if err == nil && payload.Approval != nil {
		// A236-L1: the promotion consumes its exact single-use approval with
		// the versions it writes; a replay of this event finds it consumed by
		// this same event.
		err = p.store.ConsumeOperationApprovalTx(ctx, tx, event.TenantID, *payload.Approval, event.ID, event.Time)
	}
	return true, err
}
