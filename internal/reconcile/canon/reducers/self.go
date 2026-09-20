// SPDX-License-Identifier: BUSL-1.1

package reducers

import (
	"context"

	"trstctl.com/trstctl/internal/reconcile/canon"
)

type SelfReducer struct {
	authorityID string
	source      SelfInventorySource
}

func NewSelfReducer(authorityID string, source SelfInventorySource) SelfReducer {
	return SelfReducer{authorityID: authorityID, source: source}
}

func (r SelfReducer) Observe(ctx context.Context, tenantID string) (Observation, error) {
	if r.authorityID == "" {
		return Observation{}, ErrMissingAuthority
	}
	if r.source == nil {
		return Observation{}, ErrMissingSource
	}
	snap, err := r.source.SelfSnapshot(ctx, tenantID)
	if err != nil {
		return Observation{}, err
	}
	wm, err := normalizeWatermark(snap.Watermark, ModeSubscription)
	if err != nil {
		return Observation{}, err
	}
	observed := make([]canon.ObservedRecord, 0, len(snap.Certificates)+len(snap.Keys)+len(snap.Workloads))
	for _, cert := range snap.Certificates {
		observed = append(observed, selfCertObserved(r.authorityID, tenantID, cert))
	}
	for _, key := range snap.Keys {
		observed = append(observed, selfKeyObserved(r.authorityID, tenantID, key))
	}
	for _, workload := range snap.Workloads {
		observed = append(observed, selfWorkloadObserved(r.authorityID, tenantID, workload))
	}
	set, err := canon.ReduceTenant(canon.SpecVersionV1, tenantID, observed)
	if err != nil {
		return Observation{}, err
	}
	return Observation{AuthorityID: r.authorityID, TenantID: set.TenantID, Set: set, Watermark: wm}, nil
}

func selfCertObserved(authorityID, tenantID string, cert SelfCertificate) canon.ObservedRecord {
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

func selfKeyObserved(authorityID, tenantID string, key SelfKey) canon.ObservedRecord {
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

func selfWorkloadObserved(authorityID, tenantID string, workload SelfWorkloadIdentity) canon.ObservedRecord {
	return canon.ObservedRecord{
		TenantID:   tenantID,
		RecordType: canon.RecordTypeWorkloadIdentity,
		Workload:   &canon.WorkloadIdentity{SPIFFEID: workload.SPIFFEID},
		Algorithm:  workload.Algorithm,
		Status:     workload.Status,
		Provenance: canon.Provenance{AuthorityID: authorityID, NativeID: firstNonEmpty(workload.NativeID, workload.SPIFFEID)},
	}
}
