// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"reflect"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// PrepareExistingImportCSR makes custody happen before public signing material
// leaves trstctl. The global handle claim is the first-writer key fence; the
// reserved receipt is the first-writer response/event fence. Both survive a
// crash after the signer acts or after JetStream accepts the event.
func (h *caHierarchyService) PrepareExistingImportCSR(ctx context.Context, tenantID string, req api.CAPrepareExistingImportCSRRequest) (api.CAExistingImportCSR, error) {
	if req.CeremonyID == "" {
		return api.CAExistingImportCSR{}, fmt.Errorf("%w: ceremony_id is required", api.ErrCAHierarchyInvalid)
	}
	issuerDER, _, err := certificateChainPEM(req.CertificatePEM)
	if err != nil {
		return api.CAExistingImportCSR{}, err
	}
	purpose, err := preparedExistingCAPurpose(issuerDER, req.Spec, req.ParentID)
	if err != nil {
		return api.CAExistingImportCSR{}, err
	}
	if req.ParentID != "" {
		parent, err := h.store.GetCAAuthority(ctx, tenantID, req.ParentID)
		if err != nil {
			return api.CAExistingImportCSR{}, err
		}
		if err := validatePreparedCAIssuerParent(parent, issuerDER); err != nil {
			return api.CAExistingImportCSR{}, err
		}
	}
	handle := hierarchySignerHandle(req.CeremonyID)
	if err := h.claimCeremonyCASigner(ctx, tenantID, req.CeremonyID, purpose, handle); err != nil {
		return api.CAExistingImportCSR{}, err
	}
	// The external issuer signs a classical CSR; a post-quantum hierarchy is
	// minted by the served signer path, not prepared for an outside CA.
	signer, _, err := h.createOrBindSigner(ctx, handle, crypto.ECDSAP256)
	if err != nil {
		return api.CAExistingImportCSR{}, err
	}
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: req.Spec.CommonName}, signer)
	if err != nil {
		return api.CAExistingImportCSR{}, fmt.Errorf("%w: create public CA CSR: %v", api.ErrCAHierarchyInvalid, err)
	}
	issuerSHA := crypto.SHA256Hex(flattenDERChain(issuerDER))
	var actor *events.Actor
	if current, ok := events.ActorFromContext(ctx); ok {
		actor = &current
	}
	actorJSON, err := json.Marshal(actor)
	if err != nil {
		return api.CAExistingImportCSR{}, err
	}
	eventID := "ca-existing-import-csr-" + req.CeremonyID
	payload, err := json.Marshal(map[string]any{
		"ca_id":       crypto.UUIDv5OID([]byte("ca-existing-import:" + tenantID + ":" + req.CeremonyID)),
		"ceremony_id": req.CeremonyID, "signer_handle": handle,
		"csr_sha256": crypto.SHA256Hex(csrDER), "offline_root": false,
	})
	if err != nil {
		return api.CAExistingImportCSR{}, err
	}
	receipt, err := h.store.ReserveCASignerPreparation(ctx, store.CASignerPreparation{
		TenantID: tenantID, CeremonyID: req.CeremonyID, Handle: handle,
		IssuerSHA256: issuerSHA, ParentID: req.ParentID, Purpose: purpose,
		CSRPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		EventID: eventID, EventTime: time.Now().UTC().Truncate(time.Microsecond),
		EventActor: actorJSON, EventPayload: payload,
	})
	if err != nil {
		return api.CAExistingImportCSR{}, caHierarchyConflict(err)
	}
	if err := h.appendPreparedExistingCSR(ctx, receipt); err != nil {
		return api.CAExistingImportCSR{}, err
	}
	if err := h.store.CompleteCASignerPreparation(ctx, receipt); err != nil {
		return api.CAExistingImportCSR{}, caHierarchyConflict(err)
	}
	return existingImportCSRResponse(receipt), nil
}

// GetExistingImportCSR is a read-only recovery path. It returns a CSR only if
// its exact retained event exists; a reservation alone is not a completed API
// result. POST retry finishes a reservation after an interrupted append.
func (h *caHierarchyService) GetExistingImportCSR(ctx context.Context, tenantID, ceremonyID string) (api.CAExistingImportCSR, error) {
	handle := hierarchySignerHandle(ceremonyID)
	receipt, err := h.store.GetCASignerPreparation(ctx, tenantID, ceremonyID, handle)
	if err != nil {
		return api.CAExistingImportCSR{}, err
	}
	if err := h.checkPreparedExistingCSREvent(ctx, receipt); err != nil {
		return api.CAExistingImportCSR{}, err
	}
	return existingImportCSRResponse(receipt), nil
}

func existingImportCSRResponse(p store.CASignerPreparation) api.CAExistingImportCSR {
	return api.CAExistingImportCSR{
		CeremonyID: p.CeremonyID, ParentID: p.ParentID, IssuerSHA256: p.IssuerSHA256,
		CSRPem: p.CSRPEM, SignerHandle: p.Handle,
	}
}

func (h *caHierarchyService) appendPreparedExistingCSR(ctx context.Context, p store.CASignerPreparation) error {
	if _, err := h.checkPreparedExistingCSREventLookup(ctx, p, true); err != nil {
		return err
	}
	return nil
}

func (h *caHierarchyService) checkPreparedExistingCSREvent(ctx context.Context, p store.CASignerPreparation) error {
	found, err := h.checkPreparedExistingCSREventLookup(ctx, p, false)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%w: CSR preparation event is pending; retry the preparation request", api.ErrCAHierarchyConflict)
	}
	return nil
}

func (h *caHierarchyService) checkPreparedExistingCSREventLookup(ctx context.Context, p store.CASignerPreparation, appendIfMissing bool) (bool, error) {
	var actor *events.Actor
	if err := json.Unmarshal(p.EventActor, &actor); err != nil {
		return false, fmt.Errorf("%w: reserved CSR actor is malformed", api.ErrCAHierarchyConflict)
	}
	expected := events.Event{
		ID: p.EventID, Type: projections.EventCAIntermediateCSRIssued, TenantID: p.TenantID,
		Time: p.EventTime, SchemaVersion: events.DefaultSchemaVersion,
		Data: p.EventPayload, Actor: actor,
	}
	canonical, found, err := h.log.EventByID(ctx, p.EventID)
	if err != nil {
		return false, err
	}
	if !found {
		if !appendIfMissing {
			return false, nil
		}
		canonical, err = h.log.Append(ctx, expected)
		if err != nil {
			return false, err
		}
		canonical, found, err = h.log.EventByID(ctx, p.EventID)
		if err != nil {
			return false, err
		}
		if !found {
			return false, fmt.Errorf("%w: CSR event append was not retained", api.ErrCAHierarchyConflict)
		}
	}
	if canonical.ID != expected.ID || canonical.TenantID != expected.TenantID ||
		canonical.Type != expected.Type || canonical.SchemaVersion != expected.SchemaVersion ||
		!canonical.Time.Equal(expected.Time) || !bytes.Equal(canonical.Data, expected.Data) ||
		!reflect.DeepEqual(canonical.Actor, actor) {
		return false, fmt.Errorf("%w: retained CSR preparation event differs from first-writer receipt", api.ErrCAHierarchyConflict)
	}
	return true, nil
}
