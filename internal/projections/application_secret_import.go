// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

const EventApplicationSecretBatchImported = "secret.batch_imported"
const ApplicationSecretBatchImportSchemaVersion = 1
const ApplicationSecretBatchImportPrivacyTombstoneSchemaVersion = 2

type ApplicationSecretBatchImportItem struct {
	Name   string `json:"name"`
	Sealed []byte `json:"sealed"`
}

// ApplicationSecretBatchImport is one indivisible command. Values are sealed
// under each tenant/name AAD before publishing. Neither plaintext nor a raw
// Idempotency-Key enters the event log.
type ApplicationSecretBatchImport struct {
	TenantEpoch          string                             `json:"tenant_epoch"`
	IdempotencyKeyDigest string                             `json:"idempotency_key_sha256"`
	RequestBinding       string                             `json:"request_binding_hmac_sha256"`
	CommandEvidence      string                             `json:"command_evidence"`
	Surface              string                             `json:"surface"`
	Items                []ApplicationSecretBatchImportItem `json:"items"`
}

// A subject-bearing name authenticates ciphertext as AAD. Privacy rewrite
// removes only affected items; the other sealed items remain independently
// replayable under their original names and AAD. The original request binding
// remains opaque evidence for the aggregate command.
type ApplicationSecretBatchImportPrivacyPruned struct {
	ApplicationSecretBatchImport
	PrivacyDisposition         string `json:"privacy_disposition"`
	PrivacySubjectRef          string `json:"privacy_subject_ref"`
	PrivacySourceSchemaVersion int    `json:"privacy_source_schema_version"`
	PrivacyRemovedCount        int    `json:"privacy_removed_count"`
}

func init() {
	knownSchemaVersions[EventApplicationSecretBatchImported] = map[int]bool{
		ApplicationSecretBatchImportSchemaVersion:                 true,
		ApplicationSecretBatchImportPrivacyTombstoneSchemaVersion: true,
	}
	policy := events.PrivacyEventPolicy{
		Rules: []events.PrivacyFieldRule{
			{Path: "/tenant_epoch", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/idempotency_key_sha256", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/request_binding_hmac_sha256", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/command_evidence", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/surface", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/items/*/name", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/items/*/sealed", Mode: events.PrivacyFieldOpaqueExact},
		},
		PayloadShape: events.PrivacyPayloadShapeOf[ApplicationSecretBatchImport](),
	}
	if err := events.RegisterPrivacyEventPolicy(EventApplicationSecretBatchImported,
		ApplicationSecretBatchImportSchemaVersion, policy); err != nil {
		panic(err)
	}
	pruned := events.PrivacyEventPolicy{
		Rules: []events.PrivacyFieldRule{
			{Path: "/tenant_epoch", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/idempotency_key_sha256", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/request_binding_hmac_sha256", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/command_evidence", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/surface", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/items/*/name", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/items/*/sealed", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/privacy_disposition", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/privacy_subject_ref", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/privacy_source_schema_version", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/privacy_removed_count", Mode: events.PrivacyFieldOpaqueExact},
		},
		PayloadShape: events.PrivacyPayloadShapeOf[ApplicationSecretBatchImportPrivacyPruned](),
	}
	if err := events.RegisterPrivacyEventPolicy(EventApplicationSecretBatchImported,
		ApplicationSecretBatchImportPrivacyTombstoneSchemaVersion, pruned); err != nil {
		panic(err)
	}
}

func (p *Projector) applyApplicationSecretBatchImportTx(ctx context.Context, tx pgx.Tx, event events.Event) (bool, error) {
	if event.Type != EventApplicationSecretBatchImported {
		return false, nil
	}
	privacyPruned := schemaVersionOf(event) == ApplicationSecretBatchImportPrivacyTombstoneSchemaVersion
	var payload ApplicationSecretBatchImport
	if privacyPruned {
		var pruned ApplicationSecretBatchImportPrivacyPruned
		if err := decode(event, &pruned); err != nil {
			return true, err
		}
		if pruned.PrivacyDisposition != "name_items_pruned" ||
			!store.IsPrivacyReference(pruned.PrivacySubjectRef) ||
			pruned.PrivacySourceSchemaVersion != ApplicationSecretBatchImportSchemaVersion ||
			pruned.PrivacyRemovedCount < 1 || pruned.PrivacyRemovedCount+len(pruned.Items) > 100 {
			return true, errors.New("projections: invalid batch import privacy disposition")
		}
		payload = pruned.ApplicationSecretBatchImport
	} else if err := decode(event, &payload); err != nil {
		return true, err
	}
	if (!privacyPruned && len(payload.Items) == 0) || len(payload.Items) > 100 ||
		len(payload.RequestBinding) != 64 || len(payload.IdempotencyKeyDigest) != 64 ||
		len(payload.CommandEvidence) != 64 || payload.Surface != "native" || payload.TenantEpoch == "" {
		return true, errors.New("projections: incomplete application-secret batch import")
	}
	if privacyPruned && len(payload.Items) == 0 {
		return true, nil
	}
	names := make([]string, 0, len(payload.Items))
	sealed := make([]store.ApplicationSecretImportSealedItem, 0, len(payload.Items))
	for _, item := range payload.Items {
		if item.Name == "" || len(item.Sealed) == 0 {
			return true, errors.New("projections: empty application-secret batch import item")
		}
		names = append(names, item.Name)
		sealed = append(sealed, store.ApplicationSecretImportSealedItem{Name: item.Name, Sealed: item.Sealed})
	}
	if !slices.IsSorted(names) {
		return true, errors.New("projections: application-secret batch import names are not sorted")
	}
	for index := 1; index < len(names); index++ {
		if names[index] == names[index-1] {
			return true, errors.New("projections: duplicate application-secret batch import name")
		}
	}
	semantic := crypto.SHA256Hex([]byte(fmt.Sprintf("trstctl.secret.batch-import.v1\x00%s\x00%s\x00%s\x00%d\x00%s",
		event.ID, event.TenantID, event.Time.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		schemaVersionOf(event), event.Data)))
	err := p.store.ApplyApplicationSecretImportTx(ctx, tx, store.ApplicationSecretImportBatch{
		TenantID: event.TenantID, EventID: event.ID, TenantEpoch: payload.TenantEpoch,
		RequestBinding: payload.RequestBinding, Payload: event.Data,
		PayloadDigest: crypto.SHA256Hex(event.Data), Actor: event.Actor,
		EventTime: event.Time, Names: names,
	}, semantic, sealed, privacyPruned)
	if errors.Is(err, store.ErrApplicationSecretTenantEpochMismatch) {
		return true, nil
	}
	return true, err
}
