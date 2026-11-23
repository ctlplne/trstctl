// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/tenantseal"
)

// validateSealedIngressCandidate runs inside the common Append admission, after
// the current key-state A/B grants and before NATS publication. A value sealed
// before a completed rewrap cannot be published as a fresh current event.
func validateSealedIngressCandidate(ctx context.Context, access tenantseal.Access, event events.Event) error {
	check := func(sealed, aad []byte) error {
		if access == nil || len(sealed) == 0 || len(aad) == 0 {
			return fmt.Errorf("server: sealed event ingress requires current tenant custody")
		}
		verified, err := tenantseal.VerifyRewrapPair(ctx, access, event.TenantID, sealed, sealed, aad)
		if err != nil || !verified {
			return fmt.Errorf("server: sealed event ingress candidate failed current tenant authentication")
		}
		return nil
	}
	checkSync := func(sync projections.SecretSyncQueued) error {
		if sync.ID == "" || sync.Target == "" || sync.RemoteKey == "" || len(sync.Sealed) == 0 {
			return fmt.Errorf("server: sealed secret-sync ingress command is incomplete")
		}
		return check(sync.Sealed, secretSyncAAD(event.TenantID, sync.Target, sync.ID, sync.RemoteKey))
	}
	switch event.Type {
	case projections.EventLicensedCryptoMigrationStarted:
		if event.SchemaVersion != events.DefaultSchemaVersion {
			return fmt.Errorf("server: licensed-crypto migration ingress schema is unsupported")
		}
		var started projections.LicensedCryptoMigrationStarted
		if err := decodeSealedIngressPayload(event.Data, &started); err != nil {
			return err
		}
		for _, posture := range started.TLSPostures {
			if posture.RunID == "" || posture.RunID != started.RunID ||
				posture.AssetID == "" || posture.TargetRevision == "" ||
				len(posture.SealedOutboxPayload) == 0 {
				return fmt.Errorf("server: sealed TLS posture ingress identity is incomplete")
			}
			var wrapper struct {
				Format         string `json:"format"`
				Version        int    `json:"version"`
				RunID          string `json:"run_id"`
				AssetID        string `json:"asset_id"`
				TargetRevision string `json:"target_revision"`
				Sealed         []byte `json:"sealed"`
			}
			if err := decodeSealedIngressPayload(posture.SealedOutboxPayload, &wrapper); err != nil {
				return err
			}
			if wrapper.Format != "trstctl.pqc-tls-posture.sealed" || wrapper.Version != 1 ||
				wrapper.RunID != posture.RunID || wrapper.AssetID != posture.AssetID ||
				wrapper.TargetRevision != posture.TargetRevision {
				return fmt.Errorf("server: sealed TLS posture ingress wrapper differs from intent")
			}
			destination := "connector.licensed_crypto.migration.tls_posture"
			if posture.RequiredAgentID != "" {
				destination = relay.KindPQCPosture
			}
			idempotencyKey := "licensed-crypto-migration-tls:" + posture.RunID + ":" + posture.AssetID
			aad := []byte(strings.Join([]string{
				"pqc-tls-posture-outbox-v1", event.TenantID, destination, idempotencyKey,
				posture.RunID, posture.AssetID, posture.TargetRevision,
			}, "\x00"))
			if err := check(wrapper.Sealed, aad); err != nil {
				return err
			}
		}
		return nil
	case "kmip.state.object.created", "kmip.state.object.registered", "kmip.state.object.rekeyed":
		if event.SchemaVersion != events.DefaultSchemaVersion {
			return fmt.Errorf("server: KMIP state ingress schema is unsupported")
		}
		var state struct {
			ID          string `json:"id"`
			Algorithm   string `json:"algorithm,omitempty"`
			State       string `json:"state,omitempty"`
			Version     int    `json:"version,omitempty"`
			SealedKey   []byte `json:"sealed_key,omitempty"`
			ObjectType  string `json:"object_type,omitempty"`
			Length      int    `json:"length,omitempty"`
			UsageMask   int32  `json:"usage_mask,omitempty"`
			Link        string `json:"link,omitempty"`
			PublicKey   []byte `json:"public_key,omitempty"`
			Extractable *bool  `json:"extractable,omitempty"`
		}
		if err := decodeSealedIngressPayload(event.Data, &state); err != nil {
			return err
		}
		if state.ID == "" || state.Version < 1 {
			return fmt.Errorf("server: KMIP sealed state identity is incomplete")
		}
		return check(state.SealedKey,
			[]byte("trstctl.kmip.state.v1|"+event.TenantID+"|"+state.ID+"|"+strconv.Itoa(state.Version)))
	case projections.EventApplicationSecretBatchVersioned:
		var batch projections.ApplicationSecretBatchVersion
		switch event.SchemaVersion {
		case projections.ApplicationSecretBatchVersionSchemaVersion:
			if err := decodeSealedIngressPayload(event.Data, &batch); err != nil {
				return err
			}
		case projections.ApplicationSecretBatchVersionPrivacyTombstoneSchemaVersion:
			var pruned projections.ApplicationSecretBatchVersionPrivacyPruned
			if err := decodeSealedIngressPayload(event.Data, &pruned); err != nil {
				return err
			}
			batch = pruned.ApplicationSecretBatchVersion
		default:
			return fmt.Errorf("server: sealed versioned-batch ingress schema is unsupported")
		}
		if len(batch.Items) == 0 &&
			event.SchemaVersion == projections.ApplicationSecretBatchVersionSchemaVersion {
			return fmt.Errorf("server: sealed versioned-batch ingress has no items")
		}
		for _, item := range batch.Items {
			if item.Name == "" {
				return fmt.Errorf("server: sealed versioned-batch ingress item name is missing")
			}
			if err := check(item.Sealed,
				[]byte(event.TenantID+"/secret-store/"+item.Name)); err != nil {
				return err
			}
		}
		return nil
	case projections.EventSecretStaticRotationAdvanced:
		if event.SchemaVersion < events.DefaultSchemaVersion ||
			event.SchemaVersion > projections.SecretStaticRotationHostedStageSchemaVersion {
			return fmt.Errorf("server: static-rotation ingress schema is unsupported")
		}
		var advanced projections.SecretStaticRotationAdvanced
		if err := decodeSealedIngressPayload(event.Data, &advanced); err != nil {
			return err
		}
		if advanced.ID == "" {
			return fmt.Errorf("server: static-rotation ingress command is incomplete")
		}
		for _, field := range []struct {
			part   string
			sealed []byte
		}{
			{part: "prepared", sealed: advanced.SealedPreparation},
			{part: "new", sealed: advanced.SealedNew},
			{part: "old", sealed: advanced.SealedOld},
		} {
			if len(field.sealed) == 0 {
				continue
			}
			if err := check(field.sealed,
				[]byte(event.TenantID+"/static-rotation/"+advanced.ID+"/"+field.part)); err != nil {
				return err
			}
		}
		return nil
	case projections.EventSlackInstalled:
		if event.SchemaVersion != events.DefaultSchemaVersion {
			return fmt.Errorf("server: Slack install ingress schema is unsupported")
		}
		var install projections.SlackInstalled
		if err := decodeSealedIngressPayload(event.Data, &install); err != nil {
			return err
		}
		if install.TeamID == "" {
			return fmt.Errorf("server: sealed Slack install team is missing")
		}
		return check(install.SealedBotToken,
			slackBotTokenAAD(event.TenantID, install.TeamID))
	case projections.EventCodeSigningCommanded:
		if event.SchemaVersion < events.DefaultSchemaVersion ||
			event.SchemaVersion > projections.CodeSigningPrivacySafeEventSchemaVersion {
			return fmt.Errorf("server: code-signing command ingress schema is unsupported")
		}
		var command projections.CodeSigningCommanded
		if err := decodeSealedIngressPayload(event.Data, &command); err != nil {
			return err
		}
		if command.OperationID == "" || command.Mode == "" || command.RequestHash == "" {
			return fmt.Errorf("server: sealed code-signing ingress command is incomplete")
		}
		return check(command.SealedCommand,
			codeSigningCommandAAD(event.TenantID, command.OperationID, command.Mode, command.RequestHash))
	case projections.EventDynamicSecretLeasePending:
		if event.SchemaVersion < events.DefaultSchemaVersion ||
			event.SchemaVersion > projections.DynamicSecretEventSchemaVersion {
			return fmt.Errorf("server: dynamic-secret pending ingress schema is unsupported")
		}
		var pending projections.DynamicSecretLeasePending
		if err := decodeSealedIngressPayload(event.Data, &pending); err != nil {
			return err
		}
		if len(pending.SealedPreparation) == 0 {
			return nil
		}
		if pending.ID == "" || pending.Provider == "" {
			return fmt.Errorf("server: sealed dynamic-secret pending command is incomplete")
		}
		return check(pending.SealedPreparation,
			dynamicSecretPreparationAAD(event.TenantID, pending.ID, pending.Provider))
	case projections.EventDynamicSecretLeasePrepared:
		if event.SchemaVersion < events.DefaultSchemaVersion ||
			event.SchemaVersion > projections.DynamicSecretEventSchemaVersion {
			return fmt.Errorf("server: dynamic-secret prepared ingress schema is unsupported")
		}
		var prepared projections.DynamicSecretLeasePrepared
		if err := decodeSealedIngressPayload(event.Data, &prepared); err != nil {
			return err
		}
		if prepared.ID == "" || prepared.Provider == "" {
			return fmt.Errorf("server: sealed dynamic-secret preparation is incomplete")
		}
		return check(prepared.SealedPreparation,
			dynamicSecretPreparationAAD(event.TenantID, prepared.ID, prepared.Provider))
	case projections.EventDynamicSecretLeaseIssued:
		if event.SchemaVersion < events.DefaultSchemaVersion ||
			event.SchemaVersion > projections.DynamicSecretHostedIssuedSchemaVersion {
			return fmt.Errorf("server: dynamic-secret issued ingress schema is unsupported")
		}
		var issued projections.DynamicSecretLeaseIssued
		if event.SchemaVersion == projections.DynamicSecretHostedIssuedSchemaVersion {
			var hosted projections.DynamicSecretLeaseIssuedV3
			if err := decodeSealedIngressPayload(event.Data, &hosted); err != nil {
				return err
			}
			issued = hosted.DynamicSecretLeaseIssued
		} else if err := decodeSealedIngressPayload(event.Data, &issued); err != nil {
			return err
		}
		if issued.ID == "" || issued.Provider == "" {
			return fmt.Errorf("server: sealed dynamic-secret issuance is incomplete")
		}
		return check(issued.SealedCredential,
			dynamicSecretCredentialAAD(event.TenantID, issued.ID, issued.Provider))
	case "secret.version.written":
		if event.SchemaVersion != events.DefaultSchemaVersion {
			return fmt.Errorf("server: sealed secret-version ingress schema is unsupported")
		}
		var shape struct {
			Path string `json:"path"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(event.Data, &shape); err != nil {
			return fmt.Errorf("server: sealed secret-version ingress payload is invalid")
		}
		if shape.Path != "" && shape.Name == "" {
			var version struct {
				Path     string          `json:"path"`
				Version  int             `json:"version"`
				Sealed   []byte          `json:"sealed"`
				Envelope json.RawMessage `json:"envelope,omitempty"`
			}
			if err := decodeSealedIngressPayload(event.Data, &version); err != nil ||
				version.Version < 1 || len(version.Envelope) != 0 {
				return fmt.Errorf("server: sealed secret-version ingress payload is invalid")
			}
			return check(version.Sealed, []byte(event.TenantID+"|"+version.Path))
		}
		if shape.Name != "" && shape.Path == "" {
			var audit struct {
				Name                 string          `json:"name"`
				Version              int             `json:"version"`
				Sealed               []byte          `json:"sealed"`
				WrittenAt            json.RawMessage `json:"written_at"`
				RecoveredFromVersion *int            `json:"recovered_from_version,omitempty"`
			}
			if err := decodeSealedIngressPayload(event.Data, &audit); err != nil ||
				audit.Version < 1 || len(audit.WrittenAt) == 0 {
				return fmt.Errorf("server: sealed secret-version audit ingress payload is invalid")
			}
			return check(audit.Sealed, []byte(event.TenantID+"/secret-store/"+audit.Name))
		}
		return fmt.Errorf("server: sealed secret-version ingress identity is ambiguous")
	case projections.EventSecretSyncQueued:
		if event.SchemaVersion != events.DefaultSchemaVersion &&
			event.SchemaVersion != projections.SecretSyncEventSchemaVersion {
			return fmt.Errorf("server: sealed secret-sync ingress schema is unsupported")
		}
		var sync projections.SecretSyncQueued
		if err := decodeSealedIngressPayload(event.Data, &sync); err != nil {
			return err
		}
		return checkSync(sync)
	case projections.EventApplicationSecretCreated, projections.EventApplicationSecretRotated,
		projections.EventApplicationSecretRecovered, projections.EventApplicationSecretDeleted,
		projections.EventApplicationSecretUndeleted:
		var mutation projections.ApplicationSecretMutation
		switch event.SchemaVersion {
		case projections.ApplicationSecretMutationSchemaVersion:
			if err := decodeSealedIngressPayload(event.Data, &mutation); err != nil {
				return err
			}
		case projections.ApplicationSecretPrivacyDispositionSchemaVersion:
			if !hasUnclassifiedSealedIngressField(event.Data) {
				return nil // Name tombstones carry no recoverable value.
			}
			var localOnly projections.ApplicationSecretPrivacySyncErased
			if err := decodeSealedIngressPayload(event.Data, &localOnly); err != nil {
				return err
			}
			if localOnly.PrivacyDisposition != events.ApplicationSecretPrivacyDispositionSyncErased ||
				!localOnly.PrivacySyncAuthorityErased || localOnly.Sync != nil ||
				localOnly.PrivacySourceSchemaVersion != projections.ApplicationSecretMutationSchemaVersion {
				return fmt.Errorf("server: sealed privacy-disposition ingress command is invalid")
			}
			mutation = localOnly.ApplicationSecretMutation
		default:
			if hasUnclassifiedSealedIngressField(event.Data) {
				return fmt.Errorf("server: sealed application-secret ingress schema is unsupported")
			}
			return nil
		}
		if len(mutation.Sealed) != 0 {
			if mutation.Name == "" {
				return fmt.Errorf("server: sealed application-secret ingress name is missing")
			}
			if err := check(mutation.Sealed, []byte(event.TenantID+"/secret-store/"+mutation.Name)); err != nil {
				return err
			}
		}
		if mutation.Sync != nil {
			return checkSync(*mutation.Sync)
		}
		return nil
	case projections.EventApplicationSecretBatchImported:
		var batch projections.ApplicationSecretBatchImport
		switch event.SchemaVersion {
		case projections.ApplicationSecretBatchImportSchemaVersion:
			if err := decodeSealedIngressPayload(event.Data, &batch); err != nil {
				return err
			}
		case projections.ApplicationSecretBatchImportPrivacyTombstoneSchemaVersion:
			var pruned projections.ApplicationSecretBatchImportPrivacyPruned
			if err := decodeSealedIngressPayload(event.Data, &pruned); err != nil {
				return err
			}
			batch = pruned.ApplicationSecretBatchImport
		default:
			return fmt.Errorf("server: sealed batch ingress schema is unsupported")
		}
		if len(batch.Items) == 0 && event.SchemaVersion == projections.ApplicationSecretBatchImportSchemaVersion {
			return fmt.Errorf("server: sealed batch ingress has no items")
		}
		for _, item := range batch.Items {
			if item.Name == "" {
				return fmt.Errorf("server: sealed batch ingress item name is missing")
			}
			if err := check(item.Sealed, []byte(event.TenantID+"/secret-store/"+item.Name)); err != nil {
				return err
			}
		}
		return nil
	default:
		if hasUnclassifiedSealedIngressField(event.Data) {
			return fmt.Errorf("server: sealed event ingress type is not classified")
		}
		return nil
	}
}

func decodeSealedIngressPayload(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("server: sealed event ingress payload is invalid: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("server: sealed event ingress payload has trailing content")
	}
	return nil
}

func hasUnclassifiedSealedIngressField(data []byte) bool {
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return bytes.Contains(bytes.ToLower(data), []byte("sealed"))
	}
	var walk func(any) bool
	walk = func(current any) bool {
		switch typed := current.(type) {
		case map[string]any:
			for name, child := range typed {
				if sealedIngressFieldName(name) {
					return true
				}
				if walk(child) {
					return true
				}
			}
		case []any:
			for _, child := range typed {
				if walk(child) {
					return true
				}
			}
		}
		return false
	}
	return walk(value)
}

func sealedIngressFieldName(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "sealed_at", "sealed_sha256", "sealed_only_floor", "sealed_results",
		"sealed_tenants_not_opened", "sealed_copies", "ciphertext_sha256":
		return false
	}
	return lower == "sealed" || strings.HasPrefix(lower, "sealed_") ||
		lower == "requester_sealed" || lower == "ciphertext" ||
		strings.HasPrefix(lower, "ciphertext_")
}
