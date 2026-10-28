// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A209: a managed CA leaf recorded by a v1 ca.endentity.issued event kept only
// its serial, so the inventory revocation workflow could not reach it (A113
// recovers the v2 responder form, which retained the leaf). An operator who
// still holds the public certificate supplies it: it is accepted only when one
// of the tenant's managed CAs signed it, by that CA's stored certificate, and
// a v1 mint of that CA recorded its serial. The leaf then gets the inventory
// row a managed mint would have had, with custody unknown.

var managedCARecoveryNamespace = uuid.MustParse("3c0e1f6a-5d2b-4a7e-9f18-7b6c2a90d4e3")

// managedCARecoveryEventID is the one recovery event an original mint gets.
func managedCARecoveryEventID(tenantID, originalEventID string) string {
	return uuid.NewSHA1(managedCARecoveryNamespace, []byte(tenantID+"\x00"+originalEventID)).String()
}

// RecoverManagedCALeaf gives a serial-only managed CA leaf its inventory row
// from the public certificate an operator supplies. Retrying returns the same
// row.
func (s *Server) RecoverManagedCALeaf(ctx context.Context, tenantID string, certificatePEM []byte) (api.PKISecretLeafRecovery, error) {
	if s.log == nil || s.store == nil {
		return api.PKISecretLeafRecovery{}, errors.New("server: managed CA leaf recovery requires the event log and store")
	}
	der, err := certinfo.LeafDER(certificatePEM)
	if err != nil {
		return api.PKISecretLeafRecovery{}, fmt.Errorf("%w: the body is not one PEM certificate: %v", api.ErrPKISecretLeafNotRecoverable, err)
	}
	info, err := certinfo.Inspect(der)
	if err != nil || info.IsCA {
		return api.PKISecretLeafRecovery{}, fmt.Errorf("%w: the certificate is not an end-entity leaf", api.ErrPKISecretLeafNotRecoverable)
	}
	authority, authorityDER, err := s.managedCAThatSigned(ctx, tenantID, der)
	if err != nil {
		return api.PKISecretLeafRecovery{}, err
	}
	mint, found, err := s.managedCAMintForSerial(ctx, tenantID, authority.ID, info.SerialNumber)
	if err != nil {
		return api.PKISecretLeafRecovery{}, err
	}
	if !found {
		return api.PKISecretLeafRecovery{}, fmt.Errorf("%w: no managed CA mint of %s recorded serial %s", api.ErrPKISecretLeafNotRecoverable,
			authority.CommonName, info.SerialNumber)
	}
	if mint.SchemaVersion != 1 {
		// A later mint retained the leaf: it is inventoried by its own event or
		// by the lifecycle recovery (A113), never from an operator's copy.
		return api.PKISecretLeafRecovery{}, fmt.Errorf("%w: its mint retained the certificate; the lifecycle recovery inventories it", api.ErrPKISecretLeafInInventory)
	}
	evidence := projections.RecoveredFromOperatorManagedLeaf
	out := api.PKISecretLeafRecovery{
		CertificateID: projections.RecoveredInventoryID(tenantID, projections.CACertificateInventoryRecovered{
			OriginalEventID: mint.ID, Evidence: evidence}),
		Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint, OriginalEventID: mint.ID, Evidence: evidence,
	}
	recoveryID := managedCARecoveryEventID(tenantID, mint.ID)
	if _, found, err := s.log.EventByID(ctx, recoveryID); err != nil {
		return api.PKISecretLeafRecovery{}, err
	} else if found {
		out.AlreadyRecovered = true
		return out, nil
	}
	if existing, err := s.store.GetCertificateByFingerprint(ctx, tenantID, info.SHA256Fingerprint); err == nil {
		return api.PKISecretLeafRecovery{}, fmt.Errorf("%w: as %s", api.ErrPKISecretLeafInInventory, existing.ID)
	} else if !store.IsNotFound(err) {
		return api.PKISecretLeafRecovery{}, err
	}
	if err := s.appendPKISecretRecovery(ctx, tenantID, mint.ID, recoveryID, authority.ID, info.SerialNumber,
		info.SHA256Fingerprint, der, authorityDER, evidence); err != nil {
		return api.PKISecretLeafRecovery{}, err
	}
	return out, nil
}

// managedCAThatSigned finds the tenant's managed CA whose stored certificate
// signed the leaf.
func (s *Server) managedCAThatSigned(ctx context.Context, tenantID string, leafDER []byte) (store.CAAuthority, []byte, error) {
	authorities, err := s.store.ListCAAuthorities(ctx, tenantID)
	if err != nil {
		return store.CAAuthority{}, nil, err
	}
	for _, authority := range authorities {
		caDER, err := certinfo.LeafDER([]byte(authority.CertificatePEM))
		if err != nil || len(caDER) == 0 {
			continue
		}
		if crypto.VerifyLeafSignedByCA(leafDER, caDER) == nil {
			return authority, bytes.Clone(caDER), nil
		}
	}
	return store.CAAuthority{}, nil, fmt.Errorf("%w: none of this tenant's managed CAs signed the certificate", api.ErrPKISecretLeafNotRecoverable)
}

// managedCAMintForSerial finds the ca.endentity.issued mint of serial under
// the managed CA in the tenant's retained history.
func (s *Server) managedCAMintForSerial(ctx context.Context, tenantID, caID, serial string) (events.Event, bool, error) {
	var (
		mint  events.Event
		found bool
	)
	err := s.log.WithHistoryRead(ctx, func(readCtx context.Context) error {
		head, err := s.log.LastSequence(readCtx)
		if err != nil || head == 0 {
			return err
		}
		return s.log.ReplayTenantTypesThrough(readCtx, tenantID, 1, head, []string{projections.EventCAEndEntityIssued}, func(e events.Event) error {
			if found {
				return nil
			}
			var fact struct {
				CAID   string `json:"ca_id"`
				Serial string `json:"serial"`
			}
			if err := json.Unmarshal(e.Data, &fact); err != nil {
				return fmt.Errorf("server: decode managed CA mint %s: %w", e.ID, err)
			}
			if fact.CAID == caID && fact.Serial == serial {
				mint, found = e, true
			}
			return nil
		})
	})
	return mint, found, err
}
