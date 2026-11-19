// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"errors"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/hostedkey"
	"trstctl.com/trstctl/internal/store"
)

const (
	SecretStaticRotationReferenceQueueSchemaVersion = 2
	SecretStaticRotationBoundQueueSchemaVersion     = 3
	SecretStaticRotationHostedStageSchemaVersion    = 3
	SecretRotationScheduleReferenceSchemaVersion    = 2
	SecretRotationScheduleControlViewSchemaVersion  = 3
)

type SecretStaticRotationReferenceQueued struct {
	SecretStaticRotationQueued
	ReferenceProviderType string `json:"reference_provider_type"`
}

// SecretStaticRotationBoundQueued records that the writer checked a native
// predecessor under the exact tenant, provider, key and expected version.
type SecretStaticRotationBoundQueued struct {
	SecretStaticRotationQueued
	ProviderAuthority string    `json:"provider_authority"`
	ReceiverAuthority string    `json:"receiver_authority,omitempty"`
	SecretCreatedAt   time.Time `json:"secret_created_at"`
	SecretUpdatedAt   time.Time `json:"secret_updated_at"`
}

type SecretRotationScheduleReferenceUpserted struct {
	SecretRotationScheduleUpserted
	ReferenceProviderType string `json:"reference_provider_type"`
}

func decodeSecretRotationScheduleReference(e events.Event) (SecretRotationScheduleUpserted, string, error) {
	var schedule SecretRotationScheduleUpserted
	if schemaVersionOf(e) == 1 {
		err := decode(e, &schedule)
		return schedule, "", err
	}
	var source SecretRotationScheduleReferenceUpserted
	if err := decode(e, &source); err != nil {
		return schedule, "", err
	}
	if _, hosted := hostedkey.Providers[source.ReferenceProviderType]; !hosted && source.ReferenceProviderType != store.SecretRotationScheduleNativeReference {
		return schedule, "", errors.New("projections: rotation schedule has an invalid reference provider type")
	}
	return source.SecretRotationScheduleUpserted, source.ReferenceProviderType, nil
}

// SecretStaticRotationHostedStaged attests the public reference check at
// staging. It applies to a guarded successor even when the command was queued
// by an older writer.
type SecretStaticRotationHostedStaged struct {
	ID           string `json:"id"`
	TenantEpoch  string `json:"tenant_epoch"`
	FromPhase    string `json:"from_phase"`
	Phase        string `json:"phase"`
	ProviderType string `json:"provider_type"`
	NewRef       string `json:"new_ref"`
	SealedNew    []byte `json:"sealed_new"`
}

func DecodeSecretStaticRotationQueueSource(e events.Event) (SecretStaticRotationQueued, string, error) {
	var queued SecretStaticRotationQueued
	if e.Type != EventSecretStaticRotationQueued {
		return queued, "", errors.New("projections: unexpected static rotation queue source")
	}
	if schemaVersionOf(e) == 1 {
		err := decode(e, &queued)
		return queued, "", err
	}
	if schemaVersionOf(e) == SecretStaticRotationBoundQueueSchemaVersion {
		bound, err := DecodeSecretStaticRotationBoundQueueSource(e)
		return bound.SecretStaticRotationQueued, store.SecretRotationScheduleNativeReference, err
	}
	if schemaVersionOf(e) != SecretStaticRotationReferenceQueueSchemaVersion {
		return queued, "", errors.New("projections: unsupported static rotation queue schema")
	}
	var source SecretStaticRotationReferenceQueued
	if err := decode(e, &source); err != nil {
		return queued, "", err
	}
	if _, ok := hostedkey.Providers[source.ReferenceProviderType]; !ok && source.ReferenceProviderType != store.SecretRotationScheduleNativeReference {
		return queued, "", errors.New("projections: static rotation reference evidence has an invalid provider type")
	}
	return source.SecretStaticRotationQueued, source.ReferenceProviderType, nil
}

func DecodeSecretStaticRotationBoundQueueSource(e events.Event) (SecretStaticRotationBoundQueued, error) {
	var bound SecretStaticRotationBoundQueued
	if e.Type != EventSecretStaticRotationQueued || schemaVersionOf(e) != SecretStaticRotationBoundQueueSchemaVersion {
		return bound, errors.New("projections: unexpected bound static rotation queue source")
	}
	if err := decode(e, &bound); err != nil {
		return bound, err
	}
	if len(bound.ProviderAuthority) != 64 || bound.ReceiverAuthority != "" && len(bound.ReceiverAuthority) != 64 ||
		bound.SecretCreatedAt.IsZero() || bound.SecretUpdatedAt.IsZero() || bound.ProviderBinding != "" {
		return bound, errors.New("projections: incomplete native predecessor authority")
	}
	return bound, nil
}

func DecodeSecretStaticRotationHostedStage(e events.Event) (SecretStaticRotationHostedStaged, error) {
	var stage SecretStaticRotationHostedStaged
	if e.Type != EventSecretStaticRotationAdvanced || schemaVersionOf(e) != SecretStaticRotationHostedStageSchemaVersion {
		return stage, errors.New("projections: unexpected guarded static rotation stage source")
	}
	if err := decode(e, &stage); err != nil {
		return stage, err
	}
	if _, ok := hostedkey.Providers[stage.ProviderType]; !ok || stage.ID == "" || stage.TenantEpoch == "" ||
		stage.FromPhase != store.SecretStaticRotationQueued || stage.Phase != store.SecretStaticRotationStaged ||
		stage.NewRef == "" || len(stage.SealedNew) == 0 {
		return stage, errors.New("projections: guarded static rotation stage is incomplete")
	}
	return stage, nil
}
