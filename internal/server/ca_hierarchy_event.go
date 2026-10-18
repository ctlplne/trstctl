// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

func (h *caHierarchyService) appendAuthorityCreatedEventTx(ctx context.Context, tx pgx.Tx, tenantID, eventType string, authority store.CAAuthority, ceremonyID string, offlineRoot bool, chainSHA256 string) (events.Event, error) {
	ev, err := h.appendVersionedEvent(ctx, tenantID, eventType, projections.CAAuthorityCreatedEventSchemaVersion, caAuthorityCreatedPayload(authority, ceremonyID, offlineRoot, chainSHA256))
	if err != nil {
		return events.Event{}, err
	}
	if err := projections.New(h.store).ApplyTx(ctx, tx, ev); err != nil {
		return ev, err
	}
	return ev, nil
}

func caAuthorityCreatedPayload(authority store.CAAuthority, ceremonyID string, offlineRoot bool, chainSHA256 string) projections.CAAuthorityCreated {
	notAfter := time.Time{}
	if authority.NotAfter != nil {
		notAfter = *authority.NotAfter
	}
	return projections.CAAuthorityCreated{
		CAID: authority.ID, ParentID: authority.ParentID, CommonName: authority.CommonName,
		Kind: authority.Kind, CertificatePEM: authority.CertificatePEM, SignerHandle: authority.SignerHandle,
		Serial: authority.Serial, NotAfter: notAfter, MaxPathLen: authority.MaxPathLen,
		PermittedDNSNames: authority.PermittedDNSNames, EKUs: authority.EKUs,
		CeremonyID: ceremonyID, OfflineRoot: offlineRoot, ChainSHA256: chainSHA256,
	}
}
