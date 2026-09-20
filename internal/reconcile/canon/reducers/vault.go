// SPDX-License-Identifier: BUSL-1.1

package reducers

import (
	"context"
	"encoding/hex"
	"fmt"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/reconcile/canon"
)

type VaultReducer struct {
	cfg    ReducerConfig
	source VaultInventorySource
}

func NewVaultReducer(cfg ReducerConfig, source VaultInventorySource) VaultReducer {
	return VaultReducer{cfg: cfg, source: source}
}

func (r VaultReducer) Observe(ctx context.Context, tenantID string) (Observation, error) {
	cfg, err := validateConfig(r.cfg)
	if err != nil {
		return Observation{}, err
	}
	if r.source == nil {
		return Observation{}, ErrMissingSource
	}
	sb := NewObservationSandbox(cfg.Grant, cfg.Transport)
	snap, err := r.source.VaultSnapshot(ctx, tenantID, sb)
	if err != nil {
		return Observation{}, err
	}
	wm, err := normalizeWatermark(snap.Watermark, cfg.Mode)
	if err != nil {
		return Observation{}, err
	}

	observed := make([]canon.ObservedRecord, 0, len(snap.Secrets)+len(snap.PKICertificates)+len(snap.Keys))
	for i := range snap.Secrets {
		rec, err := vaultSecretObserved(cfg.AuthorityID, tenantID, &snap.Secrets[i])
		if err != nil {
			return Observation{}, err
		}
		observed = append(observed, rec)
	}
	for _, cert := range snap.PKICertificates {
		observed = append(observed, vaultPKIObserved(cfg.AuthorityID, tenantID, cert))
	}
	for _, key := range snap.Keys {
		observed = append(observed, vaultKeyObserved(cfg.AuthorityID, tenantID, key))
	}
	set, err := canon.ReduceTenant(canon.SpecVersionV1, tenantID, observed)
	if err != nil {
		return Observation{}, err
	}
	return Observation{AuthorityID: cfg.AuthorityID, TenantID: set.TenantID, Set: set, Watermark: wm, Denied: sb.Denied()}, nil
}

func vaultSecretObserved(authorityID, tenantID string, secretRef *VaultSecretRef) (canon.ObservedRecord, error) {
	if len(secretRef.Value) > 0 {
		secret.Wipe(secretRef.Value)
		secretRef.Value = nil
	}
	attrs := map[string]canon.Value{}
	if secretRef.ProviderVersionID != "" {
		attrs["provider_version_id"] = canon.String(secretRef.ProviderVersionID)
	}
	if secretRef.ProviderValueSHA256Hex != "" {
		hash, err := hex.DecodeString(secretRef.ProviderValueSHA256Hex)
		if err != nil {
			return canon.ObservedRecord{}, fmt.Errorf("xrec reducers: vault provider value sha256: %w", err)
		}
		attrs["value_sha256"] = canon.Bytes(hash)
	}
	return canon.ObservedRecord{
		TenantID:   tenantID,
		RecordType: canon.RecordTypeSecretRef,
		SecretRef:  &canon.SecretRefIdentity{Namespace: secretRef.Namespace, Path: secretRef.Path},
		Algorithm:  "unknown",
		Validity: canon.ValidityInput{
			CreatedAt: timePtr(secretRef.CreatedAt),
			DeletedAt: timePtr(secretRef.DeletedAt),
		},
		Status: secretRef.Status,
		Provenance: canon.Provenance{
			AuthorityID: authorityID,
			NativeID:    firstNonEmpty(secretRef.ProviderNativeResourceID, secretRef.Path),
		},
		Attributes: nilIfEmpty(attrs),
	}, nil
}

func vaultPKIObserved(authorityID, tenantID string, cert VaultPKICertificate) canon.ObservedRecord {
	attrs := map[string]canon.Value{}
	if cert.SubjectDN != "" {
		attrs["subject_dn"] = canon.DN(cert.SubjectDN)
	}
	return canon.ObservedRecord{
		TenantID:   tenantID,
		RecordType: canon.RecordTypeX509Certificate,
		X509:       &canon.X509Identity{IssuerNameDER: append([]byte(nil), cert.IssuerNameDER...), SerialHex: cert.SerialHex},
		Algorithm:  cert.Algorithm,
		Validity: canon.ValidityInput{
			NotBefore: timePtr(cert.NotBefore),
			NotAfter:  timePtr(cert.NotAfter),
		},
		Status:     cert.Status,
		Provenance: canon.Provenance{AuthorityID: authorityID, NativeID: cert.NativeID},
		Attributes: nilIfEmpty(attrs),
	}
}

func vaultKeyObserved(authorityID, tenantID string, key VaultKey) canon.ObservedRecord {
	return canon.ObservedRecord{
		TenantID:   tenantID,
		RecordType: canon.RecordTypeKey,
		Key:        &canon.KeyIdentity{LogicalID: key.LogicalID},
		Algorithm:  key.Algorithm,
		Validity: canon.ValidityInput{
			CreatedAt: timePtr(key.CreatedAt),
			DeletedAt: timePtr(key.DeletedAt),
		},
		Status:     key.Status,
		Provenance: canon.Provenance{AuthorityID: authorityID, NativeID: firstNonEmpty(key.NativeID, key.LogicalID)},
	}
}

func nilIfEmpty(attrs map[string]canon.Value) map[string]canon.Value {
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
