// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Factory provisioning for devices (P12), on the server side. A batch stands
// on one active edge delegation; a station's journal reconciles through the
// edge ledger (so every birth certificate is in the edge inventory with its
// constraint check) and then into the batch, counted against its quota.

// factoryESTPath is where devices enroll on first boot and renew.
const factoryESTPath = "/.well-known/est/factory"

type factoryBatchService struct {
	edge  *edgeDelegationService
	store *store.Store
	orch  *orchestrator.Orchestrator
}

func (f *factoryBatchService) activeDelegation(ctx context.Context, tenantID, id string) (store.EdgeDelegation, []byte, error) {
	d, found, err := f.store.GetEdgeDelegation(ctx, tenantID, strings.TrimSpace(id))
	if err != nil {
		return store.EdgeDelegation{}, nil, err
	}
	if !found || d.RevokedAt != nil || d.Status == "revoked" || !d.NotAfter.After(time.Now()) {
		return store.EdgeDelegation{}, nil, api.ErrFactoryDelegationUnusable
	}
	der, err := firstCertDER(d.CertificatePEM)
	if err != nil {
		return store.EdgeDelegation{}, nil, err
	}
	return d, der, nil
}

// CreateFactoryBatch records a batch on an active delegation.
func (f *factoryBatchService) CreateFactoryBatch(ctx context.Context, tenantID, creator string, req api.FactoryBatchRequest) (api.FactoryBatch, error) {
	if _, _, err := f.activeDelegation(ctx, tenantID, req.DelegationID); err != nil {
		return api.FactoryBatch{}, err
	}
	id := uuid.NewString()
	if err := f.orch.CreateFactoryBatch(ctx, tenantID, projections.FactoryBatchCreated{ID: id, DelegationID: req.DelegationID,
		Label: req.Label, Quota: req.Quota, BirthTTLSeconds: req.BirthTTLSeconds, OperationalProfile: req.OperationalProfile,
		CreatedBy: creator, DeviceAttestationRootsPEM: req.DeviceAttestationRootsPEM}); err != nil {
		return api.FactoryBatch{}, err
	}
	detail, err := f.GetFactoryBatch(ctx, tenantID, id)
	return detail.FactoryBatch, err
}

func factoryBatchView(b store.FactoryBatch, enrolled int) api.FactoryBatch {
	return api.FactoryBatch{ID: b.ID, DelegationID: b.DelegationID, Label: b.Label, Quota: b.Quota, BirthTTLSeconds: b.BirthTTLSeconds,
		OperationalProfile: b.OperationalProfile, CreatedBy: b.CreatedBy, CreatedAt: b.CreatedAt, Recorded: b.Recorded,
		OverQuota: b.OverQuota, Enrolled: enrolled, DeviceAttestationRootsPEM: b.DeviceAttestationRootsPEM, Unattested: b.Unattested}
}

// ListFactoryBatches lists the tenant's batches.
func (f *factoryBatchService) ListFactoryBatches(ctx context.Context, tenantID string) ([]api.FactoryBatch, error) {
	batches, err := f.store.ListFactoryBatches(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]api.FactoryBatch, 0, len(batches))
	for _, b := range batches {
		births, err := f.store.ListFactoryBirths(ctx, tenantID, b.ID, maxFactoryBirthRows)
		if err != nil {
			return nil, err
		}
		out = append(out, factoryBatchView(b, enrolledBirths(births)))
	}
	return out, nil
}

const maxFactoryBirthRows = 10000

func enrolledBirths(births []store.FactoryBirth) int {
	n := 0
	for _, b := range births {
		if b.Enrolled {
			n++
		}
	}
	return n
}

// GetFactoryBatch reads a batch with its birth certificates.
func (f *factoryBatchService) GetFactoryBatch(ctx context.Context, tenantID, id string) (api.FactoryBatchDetail, error) {
	b, err := f.store.GetFactoryBatch(ctx, tenantID, id)
	if errors.Is(err, store.ErrFactoryBatchNotFound) {
		return api.FactoryBatchDetail{}, api.ErrFactoryBatchNotFound
	}
	if err != nil {
		return api.FactoryBatchDetail{}, err
	}
	births, err := f.store.ListFactoryBirths(ctx, tenantID, id, maxFactoryBirthRows)
	if err != nil {
		return api.FactoryBatchDetail{}, err
	}
	detail := api.FactoryBatchDetail{FactoryBatch: factoryBatchView(b, enrolledBirths(births)), Births: make([]api.FactoryBirth, 0, len(births))}
	for _, birth := range births {
		detail.Births = append(detail.Births, api.FactoryBirth{Serial: birth.Serial, DeviceName: birth.DeviceName,
			Fingerprint: birth.Fingerprint, NotAfter: birth.NotAfter, OverQuota: birth.OverQuota, Enrolled: birth.Enrolled,
			EnrolledAt: birth.EnrolledAt, OperationalSerial: birth.OperationalSerial, Renewals: birth.Renewals, Attestation: birth.Attestation})
	}
	return detail, nil
}

// FactoryBatchManifest is what the operator carries to the station.
func (f *factoryBatchService) FactoryBatchManifest(ctx context.Context, tenantID, id string) (api.FactoryManifest, error) {
	b, err := f.store.GetFactoryBatch(ctx, tenantID, id)
	if errors.Is(err, store.ErrFactoryBatchNotFound) {
		return api.FactoryManifest{}, api.ErrFactoryBatchNotFound
	}
	if err != nil {
		return api.FactoryManifest{}, err
	}
	_, der, err := f.activeDelegation(ctx, tenantID, b.DelegationID)
	if err != nil {
		return api.FactoryManifest{}, err
	}
	return api.FactoryManifest{BatchID: b.ID, TenantID: tenantID, DelegationID: b.DelegationID,
		DelegationFingerprint: crypto.SHA256Hex(der), Label: b.Label, Quota: b.Quota, BirthTTLSeconds: b.BirthTTLSeconds,
		ESTPath: factoryESTPath, DeviceAttestationRootsPEM: b.DeviceAttestationRootsPEM}, nil
}

// ReconcileFactoryBatch records a station's journal: each birth certificate
// that chains to the batch's delegation goes through the edge ledger and is
// then counted against the quota once.
func (f *factoryBatchService) ReconcileFactoryBatch(ctx context.Context, tenantID, id string, req api.FactoryReconcileRequest) (api.FactoryReconcileResult, error) {
	var out api.FactoryReconcileResult
	b, err := f.store.GetFactoryBatch(ctx, tenantID, id)
	if errors.Is(err, store.ErrFactoryBatchNotFound) {
		return out, api.ErrFactoryBatchNotFound
	}
	if err != nil {
		return out, err
	}
	d, found, err := f.store.GetEdgeDelegation(ctx, tenantID, b.DelegationID)
	if err != nil {
		return out, err
	}
	if !found {
		return out, api.ErrFactoryDelegationUnusable
	}
	delegationDER, err := firstCertDER(d.CertificatePEM)
	if err != nil {
		return out, err
	}
	attestations := make(map[string]api.FactoryAttestation, len(req.Attestations))
	for _, a := range req.Attestations {
		attestations[strings.ToLower(strings.TrimSpace(a.CertificateSHA256))] = a
	}
	for _, reportPEM := range req.CertificatesPEM {
		block, _ := pem.Decode([]byte(reportPEM))
		if block == nil || block.Type != "CERTIFICATE" {
			out.Rejected++
			continue
		}
		if _, err := crypto.InspectEdgeReportedLeaf(delegationDER, block.Bytes); err != nil {
			out.Rejected++
			continue
		}
		info, err := certinfo.Inspect(block.Bytes)
		if err != nil {
			out.Rejected++
			continue
		}
		if _, err := f.edge.Reconcile(ctx, tenantID, b.DelegationID, api.EdgeReconcileRequest{Host: req.Host,
			CertificatesPEM: []string{reportPEM}}); err != nil {
			return out, err
		}
		attestation := factoryBirthAttestation(tenantID, b, info.CommonName, block.Bytes, attestations)
		over, err := f.orch.RecordFactoryBirth(ctx, tenantID, projections.FactoryBirthRecorded{BatchID: b.ID,
			Serial: strings.ToLower(info.SerialNumber), DeviceName: info.CommonName, Fingerprint: strings.ToLower(info.SHA256Fingerprint),
			CertificateDER: block.Bytes, NotAfter: info.NotAfter, Attestation: attestation})
		switch {
		case errors.Is(err, orchestrator.ErrFactoryBirthRecorded):
			out.Already++
		case err != nil:
			return out, err
		case over:
			out.OverQuota++
		default:
			out.Recorded++
		}
		if err == nil && (attestation == store.FactoryAttestationMissing || attestation == store.FactoryAttestationRefused) {
			out.Unattested++
		}
	}
	return out, nil
}

// factoryBirthAttestation checks a birth's device attestation again at
// reconcile (P12-L1), in a batch with device attestation roots: the station's
// word is not taken. Verified only when the journal carries the device's
// attestation and CSR for this exact certificate, bound to the tenant, the
// batch and the device's name, device-bound, against the batch's roots, and
// the certificate certifies the attested key; missing when the journal
// carries none; refused otherwise. A batch with no roots records nothing.
func factoryBirthAttestation(tenantID string, b store.FactoryBatch, device string, certificateDER []byte, attestations map[string]api.FactoryAttestation) string {
	if len(b.DeviceAttestationRootsPEM) == 0 {
		return ""
	}
	a, ok := attestations[strings.ToLower(crypto.SHA256Hex(certificateDER))]
	if !ok || len(a.Credential) == 0 {
		return store.FactoryAttestationMissing
	}
	block, _ := pem.Decode([]byte(a.CSRPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return store.FactoryAttestationRefused
	}
	roots := make([][]byte, 0, len(b.DeviceAttestationRootsPEM))
	for _, root := range b.DeviceAttestationRootsPEM {
		roots = append(roots, []byte(root))
	}
	if err := deviceattest.VerifyFactoryDeviceAttestation(a.Credential, tenantID, b.ID, device, block.Bytes, certificateDER, roots, time.Now().UTC()); err != nil {
		return store.FactoryAttestationRefused
	}
	return store.FactoryAttestationVerified
}
