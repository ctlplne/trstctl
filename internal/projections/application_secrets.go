// SPDX-License-Identifier: MPL-2.0

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

const (
	EventApplicationSecretCreated   = "secret.created"
	EventApplicationSecretRotated   = "secret.rotated"
	EventApplicationSecretRecovered = "secret.recovered"
	EventApplicationSecretDeleted   = "secret.deleted"

	// ApplicationSecretMutationSchemaVersion replaces the old metadata-only audit
	// shapes with a replayable sealed command carrying exact approval authority.
	ApplicationSecretMutationSchemaVersion = 2

	// ApplicationSecretPrivacyDispositionSchemaVersion is emitted only by the
	// authenticated subject-erasure generation rewrite. It either removes all
	// command authority for an AAD-bound subject-bearing name, or preserves the
	// local mutation while removing the complete connector delivery command.
	ApplicationSecretPrivacyDispositionSchemaVersion = events.ApplicationSecretPrivacyDispositionSchemaVersion
)

// ApplicationSecretMutation carries ciphertext and non-secret binding metadata
// only. CommandEvidence is a server-keyed, domain-separated HMAC-SHA256. The
// caller-controlled Idempotency-Key is never the MAC key, so a log reader cannot
// use this evidence as an offline oracle for low-entropy secret values.
type ApplicationSecretMutation struct {
	TenantEpoch          string                      `json:"tenant_epoch,omitempty"`
	Action               string                      `json:"action"`
	Name                 string                      `json:"name"`
	ExpectedVersion      int                         `json:"expected_version"`
	ResultVersion        int                         `json:"result_version"`
	Sealed               []byte                      `json:"sealed,omitempty"`
	SourceVersion        int                         `json:"source_version,omitempty"`
	SourceWrittenAt      time.Time                   `json:"source_written_at,omitempty"`
	IdempotencyKeyDigest string                      `json:"idempotency_key_sha256"`
	RequestBinding       string                      `json:"request_binding_hmac_sha256"`
	CommandEvidence      string                      `json:"command_evidence"`
	Surface              string                      `json:"surface"`
	Sync                 *SecretSyncQueued           `json:"sync,omitempty"`
	Approval             *store.OperationApprovalUse `json:"approval,omitempty"`
}

// ApplicationSecretPrivacyNameTombstone is the closed v3 replacement for a
// mutation whose secret name contains the erased subject. Sealed bytes and every
// coordinate are intentionally absent: retaining either would create recoverable
// ciphertext that can open only under the erased name's AAD.
type ApplicationSecretPrivacyNameTombstone struct {
	Action                     string `json:"action"`
	PrivacyDisposition         string `json:"privacy_disposition"`
	PrivacySubjectRef          string `json:"privacy_subject_ref"`
	PrivacySourceSchemaVersion int    `json:"privacy_source_schema_version"`
	PrivacyAuthorityTombstone  bool   `json:"privacy_authority_tombstone"`
}

// ApplicationSecretPrivacySyncErased is the closed v3 local-only command. The
// embedded v2 fields deliberately carry no Sync value, so neither connector AAD
// coordinates nor delivery ciphertext can survive or be rebuilt. The local
// Sealed value remains bound to the unchanged Name and is therefore still valid.
type ApplicationSecretPrivacySyncErased struct {
	ApplicationSecretMutation
	PrivacyDisposition         string `json:"privacy_disposition"`
	PrivacySubjectRef          string `json:"privacy_subject_ref"`
	PrivacySourceSchemaVersion int    `json:"privacy_source_schema_version"`
	PrivacySyncAuthorityErased bool   `json:"privacy_sync_authority_erased"`
}

type applicationSecretSemanticApproval struct {
	RequestID         string `json:"request_id"`
	IntentDigest      string `json:"intent_digest"`
	ResourceKind      string `json:"resource_kind"`
	ResourceID        string `json:"resource_id"`
	Action            string `json:"action"`
	FromState         string `json:"from_state,omitempty"`
	ToState           string `json:"to_state,omitempty"`
	TargetVersion     uint64 `json:"target_version"`
	RequiredApprovals int    `json:"required_approvals"`
}

// ApplicationSecretMutationSemanticDigest is the privacy-stable identity stored
// in the independent mutation receipt. It binds the immutable event envelope,
// ciphertext, state edge, request/command evidence, and every approval capability
// field except Requester. Requester is the sole authorized privacy rewrite in this
// domain: normalizing any other string would let a rewrite hide command drift.
func ApplicationSecretMutationSemanticDigest(event events.Event, payload ApplicationSecretMutation) (string, error) {
	var approval *applicationSecretSemanticApproval
	if payload.Approval != nil {
		approval = &applicationSecretSemanticApproval{
			RequestID: payload.Approval.RequestID, IntentDigest: payload.Approval.IntentDigest,
			ResourceKind: payload.Approval.ResourceKind, ResourceID: payload.Approval.ResourceID,
			Action: payload.Approval.Action, FromState: payload.Approval.FromState,
			ToState: payload.Approval.ToState, TargetVersion: payload.Approval.TargetVersion,
			RequiredApprovals: payload.Approval.RequiredApprovals,
		}
	}
	canonical, err := json.Marshal(struct {
		Domain        string                             `json:"domain"`
		EventID       string                             `json:"event_id"`
		EventType     string                             `json:"event_type"`
		TenantID      string                             `json:"tenant_id"`
		EventTime     time.Time                          `json:"event_time"`
		SchemaVersion int                                `json:"schema_version"`
		TenantEpoch   string                             `json:"tenant_epoch,omitempty"`
		Action        string                             `json:"action"`
		Name          string                             `json:"name"`
		Expected      int                                `json:"expected_version"`
		Result        int                                `json:"result_version"`
		Sealed        []byte                             `json:"sealed,omitempty"`
		SourceVersion int                                `json:"source_version,omitempty"`
		SourceTime    time.Time                          `json:"source_written_at,omitempty"`
		KeyDigest     string                             `json:"idempotency_key_sha256"`
		Binding       string                             `json:"request_binding_hmac_sha256"`
		Evidence      string                             `json:"command_evidence"`
		Surface       string                             `json:"surface"`
		Sync          *SecretSyncQueued                  `json:"sync,omitempty"`
		Approval      *applicationSecretSemanticApproval `json:"approval,omitempty"`
	}{
		Domain:  "trstctl.application-secret-mutation-receipt.v1",
		EventID: event.ID, EventType: event.Type, TenantID: event.TenantID,
		EventTime: event.Time.UTC(), SchemaVersion: schemaVersionOf(event), TenantEpoch: payload.TenantEpoch,
		Action: payload.Action, Name: payload.Name, Expected: payload.ExpectedVersion,
		Result: payload.ResultVersion, Sealed: payload.Sealed,
		SourceVersion: payload.SourceVersion, SourceTime: payload.SourceWrittenAt.UTC(),
		KeyDigest: payload.IdempotencyKeyDigest, Binding: payload.RequestBinding,
		Evidence: payload.CommandEvidence, Surface: payload.Surface, Sync: payload.Sync, Approval: approval,
	})
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(canonical), nil
}

func init() {
	for _, eventType := range []string{
		EventApplicationSecretCreated,
		EventApplicationSecretRotated,
		EventApplicationSecretRecovered,
		EventApplicationSecretDeleted,
	} {
		knownSchemaVersions[eventType] = map[int]bool{
			1:                                      true,
			ApplicationSecretMutationSchemaVersion: true,
			ApplicationSecretPrivacyDispositionSchemaVersion: true,
		}
	}
}

// ApplicationSecretApprovalBinding is the exact state/result and evidence list
// both the requester and projector derive. Putting the command digest in ToState
// makes OperationApprovalUse itself command-bound, not merely path/action-bound.
func ApplicationSecretApprovalBinding(payload ApplicationSecretMutation) (string, string, []string, error) {
	return applicationSecretApprovalBinding(payload, false)
}

func applicationSecretApprovalBinding(
	payload ApplicationSecretMutation,
	privacySyncAuthorityErased bool,
) (string, string, []string, error) {
	if payload.Name == "" || payload.ExpectedVersion < 0 || len(payload.IdempotencyKeyDigest) != 64 ||
		len(payload.RequestBinding) != 64 || len(payload.CommandEvidence) != 64 {
		return "", "", nil, fmt.Errorf("projections: application-secret approval binding is incomplete")
	}
	if payload.Action != "rotate" && payload.Sync != nil {
		return "", "", nil, fmt.Errorf("projections: non-rotation application-secret command carries a sync intent")
	}
	from := "version:" + strconv.Itoa(payload.ExpectedVersion)
	evidence := []string{
		"surface:" + payload.Surface,
		"idempotency-key-sha256:" + payload.IdempotencyKeyDigest,
		"request-binding-hmac-sha256:" + payload.RequestBinding,
		"current-version:" + strconv.Itoa(payload.ExpectedVersion),
	}
	var to string
	switch payload.Action {
	case "create":
		if payload.Surface != "native" && payload.Surface != "vault" || payload.ExpectedVersion != 0 || payload.ResultVersion != 1 || len(payload.Sealed) == 0 {
			return "", "", nil, fmt.Errorf("projections: application-secret create result is incomplete")
		}
		from = "absent"
		to = "version:1:command-hmac-sha256:" + payload.CommandEvidence
		evidence = append(evidence, "result-version:1", "command-hmac-sha256:"+payload.CommandEvidence)
	case "rotate":
		if payload.ResultVersion != payload.ExpectedVersion+1 || len(payload.Sealed) == 0 {
			return "", "", nil, fmt.Errorf("projections: application-secret rotate result is incomplete")
		}
		to = "version:" + strconv.Itoa(payload.ResultVersion) + ":command-hmac-sha256:" + payload.CommandEvidence
		evidence = append(evidence,
			"result-version:"+strconv.Itoa(payload.ResultVersion),
			"command-hmac-sha256:"+payload.CommandEvidence)
		if payload.Surface == "rotation" {
			if payload.Sync == nil && privacySyncAuthorityErased {
				break
			}
			if payload.Sync == nil || payload.Sync.SecretName != payload.Name ||
				payload.Sync.SecretVersion != int64(payload.ResultVersion) || payload.Sync.Target == "" ||
				payload.Sync.RemoteKey == "" || payload.Sync.RequestBinding != payload.RequestBinding ||
				len(payload.Sync.Sealed) == 0 {
				return "", "", nil, fmt.Errorf("projections: connector rotation sync intent is incomplete")
			}
			evidence = append(evidence,
				"sync-target:"+payload.Sync.Target,
				"sync-remote-key:"+payload.Sync.RemoteKey)
		} else if payload.Sync != nil {
			return "", "", nil, fmt.Errorf("projections: non-connector application-secret rotation carries a sync intent")
		}
	case "recover":
		if payload.ResultVersion != payload.ExpectedVersion+1 || payload.SourceVersion <= 0 || payload.SourceWrittenAt.IsZero() || len(payload.Sealed) == 0 {
			return "", "", nil, fmt.Errorf("projections: application-secret recovery result is incomplete")
		}
		sourceTime := payload.SourceWrittenAt.UTC().Format(time.RFC3339Nano)
		to = "version:" + strconv.Itoa(payload.ResultVersion) + ":recover:" + strconv.Itoa(payload.SourceVersion) + ":" + sourceTime + ":command-hmac-sha256:" + payload.CommandEvidence
		evidence = append(evidence,
			"result-version:"+strconv.Itoa(payload.ResultVersion),
			"source-version:"+strconv.Itoa(payload.SourceVersion),
			"source-written-at:"+sourceTime,
			"command-hmac-sha256:"+payload.CommandEvidence)
	case "delete":
		if payload.ResultVersion != 0 || len(payload.Sealed) != 0 {
			return "", "", nil, fmt.Errorf("projections: application-secret delete result is invalid")
		}
		to = "deleted:command-hmac-sha256:" + payload.CommandEvidence
		evidence = append(evidence, "result:deleted", "command-hmac-sha256:"+payload.CommandEvidence)
	default:
		return "", "", nil, fmt.Errorf("projections: unsupported application-secret action %q", payload.Action)
	}
	return from, to, evidence, nil
}

func (p *Projector) applyApplicationSecretTx(ctx context.Context, tx pgx.Tx, event events.Event) (bool, error) {
	action := ""
	switch event.Type {
	case EventApplicationSecretCreated:
		action = "create"
	case EventApplicationSecretRotated:
		action = "rotate"
	case EventApplicationSecretRecovered:
		action = "recover"
	case EventApplicationSecretDeleted:
		action = "delete"
	default:
		return false, nil
	}
	version := schemaVersionOf(event)
	// Version 1 events were audit metadata emitted after a direct primary-store
	// write. They remain replayable no-ops; only v2 and the local-only v3 sync
	// disposition can be authoritative commands.
	if version == 1 {
		return true, nil
	}
	var payload ApplicationSecretMutation
	privacySyncAuthorityErased := false
	if version == ApplicationSecretPrivacyDispositionSchemaVersion {
		var header struct {
			PrivacyDisposition string `json:"privacy_disposition"`
		}
		if err := decode(event, &header); err != nil {
			return true, err
		}
		switch header.PrivacyDisposition {
		case events.ApplicationSecretPrivacyDispositionNameTombstoned:
			var tombstone ApplicationSecretPrivacyNameTombstone
			if err := decode(event, &tombstone); err != nil {
				return true, err
			}
			if tombstone.Action != action ||
				tombstone.PrivacyDisposition != events.ApplicationSecretPrivacyDispositionNameTombstoned ||
				!tombstone.PrivacyAuthorityTombstone ||
				(tombstone.PrivacySourceSchemaVersion != ApplicationSecretMutationSchemaVersion &&
					tombstone.PrivacySourceSchemaVersion != ApplicationSecretPrivacyDispositionSchemaVersion) ||
				!store.IsPrivacyReference(tombstone.PrivacySubjectRef) {
				return true, fmt.Errorf("projections: %s privacy name tombstone is invalid", event.Type)
			}
			return true, nil
		case events.ApplicationSecretPrivacyDispositionSyncErased:
			var localOnly ApplicationSecretPrivacySyncErased
			if err := decode(event, &localOnly); err != nil {
				return true, err
			}
			if localOnly.PrivacyDisposition != events.ApplicationSecretPrivacyDispositionSyncErased ||
				!localOnly.PrivacySyncAuthorityErased ||
				localOnly.PrivacySourceSchemaVersion != ApplicationSecretMutationSchemaVersion ||
				!store.IsPrivacyReference(localOnly.PrivacySubjectRef) ||
				localOnly.Sync != nil {
				return true, fmt.Errorf("projections: %s privacy sync disposition is invalid", event.Type)
			}
			payload = localOnly.ApplicationSecretMutation
			privacySyncAuthorityErased = true
		default:
			return true, fmt.Errorf("projections: %s privacy disposition is unsupported", event.Type)
		}
	} else if err := decode(event, &payload); err != nil {
		return true, err
	}
	if payload.Action != action || payload.Surface != "native" && payload.Surface != "vault" && payload.Surface != "rotation" ||
		payload.Surface == "rotation" && payload.Action != "rotate" {
		return true, fmt.Errorf("projections: %s mutation binding is invalid", event.Type)
	}
	from, to, _, err := applicationSecretApprovalBinding(payload, privacySyncAuthorityErased)
	if err != nil {
		return true, err
	}
	digest, err := ApplicationSecretMutationSemanticDigest(event, payload)
	if err != nil {
		return true, err
	}
	if err := p.store.ApplyApplicationSecretMutationTx(ctx, tx, store.ApplicationSecretMutation{
		TenantID: event.TenantID, TenantEpoch: payload.TenantEpoch,
		EventID: event.ID, SemanticDigest: digest,
		RequestBinding: payload.RequestBinding, Action: payload.Action,
		Name: payload.Name, ExpectedVersion: payload.ExpectedVersion,
		ResultVersion: payload.ResultVersion, Sealed: payload.Sealed,
		SourceVersion: payload.SourceVersion, SourceWrittenAt: payload.SourceWrittenAt,
		OccurredAt: event.Time, ApprovalFrom: from, ApprovalTo: to, Approval: payload.Approval,
	}); err != nil {
		// Retained history may contain a target that was finalized in an erased
		// tenant lifecycle and appended only after the UUID was registered again.
		// It remains source evidence, but it is not a command for the current epoch.
		// Treat it as handled so ordered catch-up/rebuild advances past the inert
		// event; the live API performs the same check strictly and reports conflict.
		if errors.Is(err, store.ErrApplicationSecretTenantEpochMismatch) {
			return true, nil
		}
		return true, err
	}
	if payload.Sync == nil {
		return true, nil
	}
	if payload.Sync.TenantEpoch != "" && payload.Sync.TenantEpoch != payload.TenantEpoch {
		return true, fmt.Errorf("projections: embedded secret-sync tenant epoch differs from its application-secret command")
	}
	targetOrder, err := secretSyncTargetOrder(event.Sequence)
	if err != nil {
		return true, err
	}
	outboxPayload, err := json.Marshal(struct {
		ID             string `json:"id"`
		Key            string `json:"key"`
		Target         string `json:"target"`
		RequestBinding string `json:"request_binding,omitempty"`
		Sealed         []byte `json:"sealed"`
	}{
		ID: payload.Sync.ID, Key: payload.Sync.RemoteKey, Target: payload.Sync.Target,
		RequestBinding: payload.Sync.RequestBinding, Sealed: payload.Sync.Sealed,
	})
	if err != nil {
		return true, err
	}
	return true, p.store.ApplySecretSyncIntentTx(ctx, tx, store.SecretSyncJob{
		ID: payload.Sync.ID, TenantID: event.TenantID, TenantEpoch: payload.TenantEpoch,
		SecretName:    payload.Sync.SecretName,
		SecretVersion: payload.Sync.SecretVersion, Target: payload.Sync.Target,
		RemoteKey: payload.Sync.RemoteKey, ValueDigest: payload.Sync.ValueDigest,
		Status: store.SecretSyncJobPending, IdempotencyKey: payload.Sync.IdempotencyKey,
		TargetOrder:    targetOrder,
		RequestBinding: payload.Sync.RequestBinding, RequestedAt: event.Time, UpdatedAt: event.Time,
	}, "secret.sync."+payload.Sync.Target, outboxPayload)
}
