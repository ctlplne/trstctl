// SPDX-License-Identifier: BUSL-1.1

package reducers

import (
	"context"

	"trstctl.com/trstctl/internal/reconcile/canon"
)

type CloudKMSReducer struct {
	cfg    ReducerConfig
	source CloudKMSInventorySource
}

func NewCloudKMSReducer(cfg ReducerConfig, source CloudKMSInventorySource) CloudKMSReducer {
	return CloudKMSReducer{cfg: cfg, source: source}
}

func (r CloudKMSReducer) Observe(ctx context.Context, tenantID string) (Observation, error) {
	cfg, err := validateConfig(r.cfg)
	if err != nil {
		return Observation{}, err
	}
	if r.source == nil {
		return Observation{}, ErrMissingSource
	}
	sb := NewObservationSandbox(cfg.Grant, cfg.Transport)
	snap, err := r.source.CloudKMSSnapshot(ctx, tenantID, sb)
	if err != nil {
		return Observation{}, err
	}
	wm, err := normalizeWatermark(snap.Watermark, cfg.Mode)
	if err != nil {
		return Observation{}, err
	}
	observed := make([]canon.ObservedRecord, 0, len(snap.Keys))
	for _, key := range snap.Keys {
		observed = append(observed, kmsKeyObserved(cfg.AuthorityID, tenantID, key))
	}
	set, err := canon.ReduceTenant(canon.SpecVersionV1, tenantID, observed)
	if err != nil {
		return Observation{}, err
	}
	return Observation{AuthorityID: cfg.AuthorityID, TenantID: set.TenantID, Set: set, Watermark: wm, Denied: sb.Denied()}, nil
}

func kmsKeyObserved(authorityID, tenantID string, key CloudKMSKey) canon.ObservedRecord {
	attrs := map[string]canon.Value{"rotation_enabled": canon.Bool(key.RotationEnabled)}
	return canon.ObservedRecord{
		TenantID:   tenantID,
		RecordType: canon.RecordTypeKey,
		Key:        &canon.KeyIdentity{LogicalID: key.KeyID},
		Algorithm:  key.AlgorithmSpec,
		Validity: canon.ValidityInput{
			CreatedAt: timePtr(key.CreatedAt),
			DeletedAt: timePtr(key.DeletedAt),
		},
		Status:     key.Status,
		Provenance: canon.Provenance{AuthorityID: authorityID, NativeID: firstNonEmpty(key.NativeID, key.KeyID)},
		Attributes: attrs,
	}
}
