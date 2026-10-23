// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

func (h *caHierarchyService) RekeyAuthority(ctx context.Context, tenantID, caID string, req api.CAAuthorityRekeyRequest) (api.CAAuthorityRotation, error) {
	ceremonyID := strings.TrimSpace(req.CeremonyID)
	if caID == "" || ceremonyID == "" {
		return api.CAAuthorityRotation{}, fmt.Errorf("%w: authority id and ceremony_id are required", api.ErrCAHierarchyInvalid)
	}
	if req.TTLSeconds <= 0 {
		return api.CAAuthorityRotation{}, fmt.Errorf("%w: ttl_seconds must be positive", api.ErrCAHierarchyInvalid)
	}
	if req.TTLSeconds > math.MaxInt64/int64(time.Second) {
		return api.CAAuthorityRotation{}, fmt.Errorf("%w: ttl_seconds exceeds the supported duration range", api.ErrCAHierarchyInvalid)
	}
	if strings.TrimSpace(req.Reason) == "" {
		return api.CAAuthorityRotation{}, fmt.Errorf("%w: reason is required for rekey_ca", api.ErrCAHierarchyInvalid)
	}
	handle := hierarchySignerHandle(ceremonyID)
	current, err := h.store.GetCAAuthority(ctx, tenantID, caID)
	if err != nil {
		return api.CAAuthorityRotation{}, err
	}
	if err := validateAuthorityRekey(current); err != nil {
		return api.CAAuthorityRotation{}, err
	}
	if current.Kind == "intermediate" {
		if current.ParentID == nil || *current.ParentID == "" {
			return api.CAAuthorityRotation{}, fmt.Errorf("%w: intermediate CA has no parent authority", api.ErrCAHierarchyInvalid)
		}
		parent, err := h.store.GetCAAuthority(ctx, tenantID, *current.ParentID)
		if err != nil {
			return api.CAAuthorityRotation{}, err
		}
		if err := validateOnlineRekeyParent(parent); err != nil {
			return api.CAAuthorityRotation{}, err
		}
	}
	purpose, err := rekeyCAPurpose(caID, rekeyAuthoritySpec(current, req.TTLSeconds), req.Reason)
	if err != nil {
		return api.CAAuthorityRotation{}, err
	}
	if err := h.claimCeremonyCASigner(ctx, tenantID, ceremonyID, purpose, handle); err != nil {
		return api.CAAuthorityRotation{}, err
	}
	newID := uuid.NewString()
	var predecessor, successor store.CAAuthority
	var rekeySigner *signing.RemoteSigner
	var signerCreated bool
	eventAppended := false
	err = h.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		predecessor, err = h.store.GetCAAuthorityForUpdateTx(ctx, tx, tenantID, caID)
		if err != nil {
			return err
		}
		if err := validateAuthorityRekey(predecessor); err != nil {
			return err
		}
		if predecessor.Kind == "intermediate" {
			if predecessor.ParentID == nil || *predecessor.ParentID == "" {
				return fmt.Errorf("%w: intermediate CA has no parent authority", api.ErrCAHierarchyInvalid)
			}
			parent, err := h.store.GetCAAuthorityForUpdateTx(ctx, tx, tenantID, *predecessor.ParentID)
			if err != nil {
				return err
			}
			if err := validateOnlineRekeyParent(parent); err != nil {
				return err
			}
		}
		spec := rekeyAuthoritySpec(predecessor, req.TTLSeconds)
		purpose, err := rekeyCAPurpose(caID, spec, req.Reason)
		if err != nil {
			return err
		}
		if _, err := h.store.ConsumeKeyCeremonyTx(ctx, tx, tenantID, ceremonyID, purpose); err != nil {
			if errors.Is(err, store.ErrKeyCeremonyPurposeMismatch) {
				return fmt.Errorf("%w: reviewed re-key plan differs from this ceremony; cancel it and start a new ceremony for the current CA profile, lifetime, and reason", api.ErrCAHierarchyConflict)
			}
			return err
		}
		// A re-key stays in the predecessor's key family: an ML-DSA authority
		// re-keys to a fresh ML-DSA key, a classical one to ECDSA-P256.
		rekeyAlgorithm := crypto.ECDSAP256
		if predecessorDER, err := firstCertDER(predecessor.CertificatePEM); err == nil {
			if alg, err := crypto.SignerBackedCAKeyAlgorithm(crypto.CertificateKeyAlgorithmLabel(predecessorDER)); err == nil {
				rekeyAlgorithm = alg
			}
		}
		rekeySigner, signerCreated, err = h.createOrBindSigner(ctx, handle, rekeyAlgorithm)
		if err != nil {
			return err
		}
		issued, chainPEM, err := h.issueRekeyedCA(ctx, tx, tenantID, predecessor, rekeySigner, spec)
		if err != nil {
			return err
		}
		notAfter := issued.NotAfter
		successor = store.CAAuthority{
			ID: newID, TenantID: tenantID, ParentID: predecessor.ParentID, CommonName: spec.CommonName,
			Kind: predecessor.Kind, Status: "active", CertificatePEM: chainPEM, SignerHandle: handle,
			Serial: issued.Serial, NotAfter: &notAfter, MaxPathLen: issued.MaxPathLen,
			PermittedDNSNames: issued.PermittedDNSDomains, EKUs: issued.EKUs,
		}
		ev, err := h.appendEvent(ctx, tenantID, projections.EventCAAuthorityRekeyed, projections.CAAuthorityRekeyed{
			ID: newID, PredecessorCAID: predecessor.ID, ParentID: predecessor.ParentID,
			CommonName: successor.CommonName, Kind: successor.Kind, CertificatePEM: successor.CertificatePEM,
			SignerHandle: successor.SignerHandle, Serial: successor.Serial, NotAfter: notAfter,
			MaxPathLen: successor.MaxPathLen, PermittedDNSNames: successor.PermittedDNSNames, EKUs: successor.EKUs,
			CeremonyID: ceremonyID, Reason: strings.TrimSpace(req.Reason),
			IssuePath: caAuthorityIssuePath(predecessor.ID), ActiveIssuePath: caAuthorityIssuePath(successor.ID),
		})
		if ev.ID != "" {
			eventAppended = true
		}
		if err != nil {
			return err
		}
		if err := projections.New(h.store).ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
		predecessor.Status = "superseded"
		replacesID := predecessor.ID
		successor.ReplacesID = &replacesID
		successor.CreatedAt = ev.Time
		return nil
	})
	if err != nil {
		if signerCreated && !eventAppended && rekeySigner != nil {
			_ = rekeySigner.Destroy(ctx)
		}
		return api.CAAuthorityRotation{}, caHierarchyConflict(err)
	}
	h.rememberSigner(successor.ID, rekeySigner)
	return authorityRotationResponse(predecessor, successor), nil
}

func (h *caHierarchyService) issueRekeyedCA(ctx context.Context, tx pgx.Tx, tenantID string, predecessor store.CAAuthority, signer *signing.RemoteSigner, spec api.CASpec) (crypto.IssuedHierarchyCA, string, error) {
	switch predecessor.Kind {
	case "root":
		issued, err := crypto.SelfSignedHierarchyCA(signer, cryptoProfile(spec))
		if err != nil {
			return crypto.IssuedHierarchyCA{}, "", fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		return issued, string(issued.CertificatePEM), nil
	case "intermediate":
		if predecessor.ParentID == nil || *predecessor.ParentID == "" {
			return crypto.IssuedHierarchyCA{}, "", fmt.Errorf("%w: intermediate CA has no parent authority", api.ErrCAHierarchyInvalid)
		}
		parent, err := h.store.GetCAAuthorityForUpdateTx(ctx, tx, tenantID, *predecessor.ParentID)
		if err != nil {
			return crypto.IssuedHierarchyCA{}, "", err
		}
		if parent.Status != "active" || parent.SignerHandle == "" {
			return crypto.IssuedHierarchyCA{}, "", fmt.Errorf("%w: parent CA must be active and signer-backed for served re-key", api.ErrCAHierarchyInvalid)
		}
		parentDER, err := firstCertDER(parent.CertificatePEM)
		if err != nil {
			return crypto.IssuedHierarchyCA{}, "", err
		}
		parentSigner, err := h.signerForAuthority(ctx, parent)
		if err != nil {
			return crypto.IssuedHierarchyCA{}, "", err
		}
		issued, err := crypto.SignIntermediateHierarchyCAForSigner(parentDER, parentSigner, signer, cryptoProfile(spec))
		if err != nil {
			return crypto.IssuedHierarchyCA{}, "", fmt.Errorf("%w: %v", api.ErrCAHierarchyInvalid, err)
		}
		chain := append([]byte{}, issued.CertificatePEM...)
		chain = append(chain, []byte(parent.CertificatePEM)...)
		return issued, string(chain), nil
	default:
		return crypto.IssuedHierarchyCA{}, "", fmt.Errorf("%w: unsupported CA kind %q", api.ErrCAHierarchyInvalid, predecessor.Kind)
	}
}
