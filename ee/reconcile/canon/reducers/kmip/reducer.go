// SPDX-License-Identifier: LicenseRef-trstctl-EE

package kmip

import (
	"context"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/ee/reconcile/canon"
	"trstctl.com/trstctl/ee/reconcile/canon/reducers"
)

type Reducer struct {
	cfg    reducers.ReducerConfig
	source Source
}

func NewReducer(cfg reducers.ReducerConfig, source Source) Reducer {
	return Reducer{cfg: cfg, source: source}
}

func (r Reducer) Observe(ctx context.Context, tenantID string) (reducers.Observation, error) {
	cfg, err := normalizeConfig(r.cfg)
	if err != nil {
		return reducers.Observation{}, err
	}
	if r.source == nil {
		return reducers.Observation{}, reducers.ErrMissingSource
	}
	sb := reducers.NewObservationSandbox(cfg.Grant, cfg.Transport)
	snap, err := r.source.KMIPSnapshot(ctx, tenantID, sb)
	if err != nil {
		return reducers.Observation{}, err
	}
	wm, err := normalizeWatermark(snap.Watermark, cfg.Mode)
	if err != nil {
		return reducers.Observation{}, err
	}
	observed := make([]canon.ObservedRecord, 0, len(snap.Objects))
	for _, obj := range snap.Objects {
		rec, err := objectObserved(cfg.AuthorityID, tenantID, obj)
		if err != nil {
			return reducers.Observation{}, err
		}
		observed = append(observed, rec)
	}
	set, err := canon.ReduceTenant(canon.SpecVersionV1, tenantID, observed)
	if err != nil {
		return reducers.Observation{}, err
	}
	return reducers.Observation{AuthorityID: cfg.AuthorityID, TenantID: set.TenantID, Set: set, Watermark: wm, Denied: sb.Denied()}, nil
}

func objectObserved(authorityID, tenantID string, obj ManagedObject) (canon.ObservedRecord, error) {
	switch obj.ObjectType {
	case ObjectTypeCertificate:
		return certObserved(authorityID, tenantID, obj), nil
	case ObjectTypeSecretData, ObjectTypeOpaqueObject:
		return secretObserved(authorityID, tenantID, obj), nil
	case ObjectTypePublicKey, ObjectTypePrivateKey, ObjectTypeSymmetricKey:
		return keyObserved(authorityID, tenantID, obj), nil
	default:
		return canon.ObservedRecord{}, fmt.Errorf("xrec kmip: unsupported object type %q", obj.ObjectType)
	}
}

func keyObserved(authorityID, tenantID string, obj ManagedObject) canon.ObservedRecord {
	attrs := commonAttrs(obj)
	return canon.ObservedRecord{
		TenantID:   tenantID,
		RecordType: canon.RecordTypeKey,
		Key:        &canon.KeyIdentity{LogicalID: obj.UniqueIdentifier, SPKI: append([]byte(nil), obj.SPKI...)},
		Algorithm:  algorithmID(obj),
		Validity: canon.ValidityInput{
			CreatedAt: timePtr(obj.InitialDate),
			NotBefore: timePtr(obj.ActivationDate),
			DeletedAt: timePtr(obj.DeactivationDate),
		},
		Status:     statusID(obj.State),
		Provenance: canon.Provenance{AuthorityID: authorityID, NativeID: obj.UniqueIdentifier},
		Attributes: attrs,
	}
}

func certObserved(authorityID, tenantID string, obj ManagedObject) canon.ObservedRecord {
	attrs := commonAttrs(obj)
	if obj.SubjectDN != "" {
		attrs["subject_dn"] = canon.DN(obj.SubjectDN)
	}
	return canon.ObservedRecord{
		TenantID:   tenantID,
		RecordType: canon.RecordTypeX509Certificate,
		X509:       &canon.X509Identity{IssuerNameDER: append([]byte(nil), obj.IssuerNameDER...), SerialHex: obj.SerialHex},
		Algorithm:  algorithmID(obj),
		Validity: canon.ValidityInput{
			CreatedAt: timePtr(obj.InitialDate),
			NotBefore: timePtr(obj.ActivationDate),
			NotAfter:  timePtr(obj.DeactivationDate),
		},
		Status:     statusID(obj.State),
		Provenance: canon.Provenance{AuthorityID: authorityID, NativeID: obj.UniqueIdentifier},
		Attributes: attrs,
	}
}

func secretObserved(authorityID, tenantID string, obj ManagedObject) canon.ObservedRecord {
	attrs := commonAttrs(obj)
	return canon.ObservedRecord{
		TenantID:   tenantID,
		RecordType: canon.RecordTypeSecretRef,
		SecretRef:  &canon.SecretRefIdentity{Namespace: "kmip", Path: obj.UniqueIdentifier},
		Algorithm:  "unknown",
		Validity: canon.ValidityInput{
			CreatedAt: timePtr(obj.InitialDate),
			DeletedAt: timePtr(obj.DeactivationDate),
		},
		Status:     statusID(obj.State),
		Provenance: canon.Provenance{AuthorityID: authorityID, NativeID: obj.UniqueIdentifier},
		Attributes: attrs,
	}
}

func commonAttrs(obj ManagedObject) map[string]canon.Value {
	attrs := map[string]canon.Value{
		"kmip_object_type": canon.String(string(obj.ObjectType)),
		"kmip_state":       canon.String(string(obj.State)),
	}
	if obj.LengthBits > 0 {
		attrs["cryptographic_length"] = canon.Int(int64(obj.LengthBits))
	}
	return attrs
}

func algorithmID(obj ManagedObject) string {
	alg := strings.ToLower(strings.TrimSpace(obj.Algorithm))
	switch alg {
	case "rsa":
		if obj.LengthBits > 0 {
			return fmt.Sprintf("RSA_%d", obj.LengthBits)
		}
		return "RSA"
	case "ecdsa", "ec":
		if obj.LengthBits == 256 {
			return "ECC_NIST_P256"
		}
		return obj.Algorithm
	case "ed25519", "ed-25519":
		return "Ed25519"
	case "":
		return "unknown"
	default:
		if obj.LengthBits > 0 {
			return fmt.Sprintf("%s_%d", obj.Algorithm, obj.LengthBits)
		}
		return obj.Algorithm
	}
}

func statusID(state State) string {
	switch normalizeState(state) {
	case "active":
		return "active"
	case "preactive", "pre-active":
		return "pending"
	case "deactivated", "inactive":
		return "disabled"
	case "compromised", "revoked":
		return "revoked"
	case "destroyed", "destroyedcompromised":
		return "pending_deletion"
	default:
		return "unknown"
	}
}

func normalizeState(state State) string {
	return strings.ToLower(strings.NewReplacer(" ", "", "_", "", "-", "").Replace(strings.TrimSpace(string(state))))
}

func normalizeConfig(cfg reducers.ReducerConfig) (reducers.ReducerConfig, error) {
	if cfg.AuthorityID == "" {
		return reducers.ReducerConfig{}, reducers.ErrMissingAuthority
	}
	if cfg.Mode == "" {
		cfg.Mode = reducers.ModePoll
	}
	if cfg.Grant == nil || cfg.Grant.Empty() {
		cfg.Grant = ReadOnlyKMIPObservationGrant(cfg.Scope)
	}
	return cfg, nil
}

func normalizeWatermark(w reducers.Watermark, fallback reducers.ObservationMode) (reducers.Watermark, error) {
	if w.Mode == "" {
		w.Mode = fallback
	}
	if w.Mode == "" {
		w.Mode = reducers.ModePoll
	}
	if w.Position == "" {
		return reducers.Watermark{}, reducers.ErrMissingWatermark
	}
	if w.ObservedAt.IsZero() {
		w.ObservedAt = time.Now().UTC()
	}
	return w, nil
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
