// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/hostedkey"
	"trstctl.com/trstctl/internal/store"
)

// DynamicSecretRevocationSource is the authorization decoded from one
// retained or current request event. LegacyRef exists only for v1/v2 sources.
type DynamicSecretRevocationSource struct {
	TenantEpoch      string
	OperationID      string
	LeaseID          string
	Provider         string
	LegacyRef        string
	PreviousAttempt  string
	PreviousOutboxID int64
}

func DecodeDynamicSecretRevocationSource(e events.Event) (DynamicSecretRevocationSource, error) {
	var result DynamicSecretRevocationSource
	retry := e.Type == EventDynamicSecretLeaseRevocationRetryRequested
	if !retry && e.Type != EventDynamicSecretLeaseRevocationRequested {
		return result, errors.New("projections: unexpected dynamic-secret revoke source")
	}
	version := schemaVersionOf(e)
	switch {
	case version == DynamicSecretRevocationReferenceSchemaVersion:
		var request DynamicSecretLeaseRevocationRequestedV3
		if retry {
			var payload DynamicSecretLeaseRevocationRetryRequestedV3
			if err := decodeClosedDynamicSecretSource(e, &payload); err != nil {
				return result, err
			}
			request = payload.DynamicSecretLeaseRevocationRequestedV3
			previous := payload.PreviousAttempt
			if !validDynamicSecretRetryAttempt(request.OperationID) || previous == request.OperationID ||
				(previous != store.DynamicSecretInitialRevokeAttempt && !validDynamicSecretRetryAttempt(previous)) {
				return result, errors.New("projections: dynamic-secret retry has an invalid attempt identity")
			}
			result.PreviousAttempt = previous
		} else if err := decodeClosedDynamicSecretSource(e, &request); err != nil {
			return result, err
		}
		result.TenantEpoch = request.TenantEpoch
		result.OperationID = request.OperationID
		result.LeaseID = request.ID
		result.Provider = request.Provider
	case retry && version == DynamicSecretEventSchemaVersion:
		var request DynamicSecretLeaseRevocationRetryRequested
		if err := decode(e, &request); err != nil {
			return result, err
		}
		if request.PreviousOutboxID <= 0 || request.BackendRef == "" {
			return result, errors.New("projections: historical dynamic-secret retry requires its original predecessor")
		}
		result = DynamicSecretRevocationSource{
			TenantEpoch: request.TenantEpoch, OperationID: request.OperationID, LeaseID: request.ID,
			Provider: request.Provider, LegacyRef: request.BackendRef, PreviousOutboxID: request.PreviousOutboxID,
		}
	case !retry && (version == 1 || version == DynamicSecretEventSchemaVersion):
		var request DynamicSecretLeaseRevocationRequested
		if err := decode(e, &request); err != nil {
			return result, err
		}
		if request.BackendRef == "" {
			return result, errors.New("projections: historical dynamic-secret revoke requires its issued reference")
		}
		result = DynamicSecretRevocationSource{
			TenantEpoch: request.TenantEpoch, OperationID: request.OperationID, LeaseID: request.ID,
			Provider: request.Provider, LegacyRef: request.BackendRef,
		}
	default:
		return result, errors.New("projections: unsupported dynamic-secret revoke source schema")
	}
	if result.LeaseID == "" || result.Provider == "" ||
		version >= DynamicSecretEventSchemaVersion && (result.TenantEpoch == "" || result.OperationID == "") {
		return result, fmt.Errorf("projections: %s payload is incomplete", e.Type)
	}
	purpose := "lease-revocation-requested"
	if retry {
		purpose = "lease-revocation-retry-requested"
	}
	return result, validateDynamicSecretEventIdentity(e, result.TenantEpoch, purpose, result.OperationID)
}

func validDynamicSecretRetryAttempt(attempt string) bool {
	raw, ok := strings.CutPrefix(attempt, "dynsecret-op-")
	if !ok {
		return false
	}
	id, err := uuid.Parse(raw)
	return err == nil && id.String() == raw
}

// DecodeDynamicSecretIssuedSource returns a hosted type only when the source
// contains the guarded v3 attestation. Older bodies retain their exact format.
func DecodeDynamicSecretIssuedSource(e events.Event) (DynamicSecretLeaseIssued, string, error) {
	var lease DynamicSecretLeaseIssued
	if e.Type != EventDynamicSecretLeaseIssued {
		return lease, "", errors.New("projections: unexpected dynamic-secret issued source")
	}
	version := schemaVersionOf(e)
	if version == 1 || version == DynamicSecretEventSchemaVersion {
		err := decode(e, &lease)
		return lease, "", err
	}
	if version != DynamicSecretHostedIssuedSchemaVersion {
		return lease, "", errors.New("projections: unsupported dynamic-secret issued source schema")
	}
	var payload DynamicSecretLeaseIssuedV3
	if err := decodeClosedDynamicSecretSource(e, &payload); err != nil {
		return lease, "", err
	}
	if _, ok := hostedkey.Providers[payload.HostedProviderType]; !ok {
		return lease, "", errors.New("projections: guarded issued source has an invalid hosted provider type")
	}
	return payload.DynamicSecretLeaseIssued, payload.HostedProviderType, nil
}

func decodeClosedDynamicSecretSource(e events.Event, payload any) error {
	decoder := json.NewDecoder(bytes.NewReader(e.Data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(payload); err != nil {
		return errors.New("projections: dynamic-secret source is invalid")
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return errors.New("projections: dynamic-secret source has trailing data")
	}
	return nil
}
