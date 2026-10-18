// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
)

// caSignerClaimPartition is a fixed non-customer RLS partition. The handle
// digest is global because the signer keystore is global. Tenant data never
// becomes visible to another customer through the conflict response.
const caSignerClaimPartition = "00000000-0000-0000-0000-000000000003"

var ErrCASignerHandleClaimed = errors.New("store: CA signer handle is already claimed")

// CASignerPreparation is the exact public CSR response and immutable event
// envelope reserved under a tenant/ceremony claim before broker publish.
type CASignerPreparation struct {
	TenantID, CeremonyID, Handle, IssuerSHA256, ParentID, Purpose, CSRPEM string
	EventID                                                               string
	EventTime                                                             time.Time
	EventActor, EventPayload                                              []byte
	Status                                                                string
}

// ClaimCASignerHandle is a durable first-writer fence. It commits before key
// generation or ca.authority.* append, so an append/SQL gap cannot let another
// tenant acquire the same signer-held private key. A retry of the same ceremony
// is idempotent; a different ceremony, including one in the same tenant, is not.
func (s *Store) ClaimCASignerHandle(ctx context.Context, tenantID, ceremonyID, handle string) error {
	if tenantID == "" || tenantID == caSignerClaimPartition || ceremonyID == "" || handle == "" {
		return errors.New("store: CA signer claim requires tenant, ceremony and handle")
	}
	hash := crypto.SHA256Hex([]byte(handle))
	return s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := lockLiveTenantRegistrationTx(ctx, tx, tenantID); err != nil {
			return err
		}
		if err := setCASignerClaimScopeTx(ctx, tx); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO ca_signer_handle_claims
		        (tenant_id, handle_sha256, owner_tenant_id, owner_ceremony_id)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (tenant_id, handle_sha256) DO NOTHING`,
			caSignerClaimPartition, hash, tenantID, ceremonyID)
		if err != nil {
			return fmt.Errorf("store: claim CA signer handle: %w", err)
		}
		var ownerTenant, ownerCeremony *string
		var state string
		if err := tx.QueryRow(ctx, `SELECT owner_tenant_id::text, owner_ceremony_id::text, state
			  FROM ca_signer_handle_claims
			 WHERE tenant_id = $1 AND handle_sha256 = $2`,
			caSignerClaimPartition, hash).Scan(&ownerTenant, &ownerCeremony, &state); err != nil {
			return fmt.Errorf("store: read CA signer claim: %w", err)
		}
		if state != "claimed" || ownerTenant == nil || ownerCeremony == nil ||
			*ownerTenant != tenantID || *ownerCeremony != ceremonyID {
			return ErrCASignerHandleClaimed
		}
		return nil
	})
}

func setCASignerClaimScopeTx(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, "SET LOCAL search_path TO public"); err != nil {
		return fmt.Errorf("store: route CA signer claim partition: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id', $1, true)`, caSignerClaimPartition); err != nil {
		return fmt.Errorf("store: scope CA signer claim partition: %w", err)
	}
	return nil
}

// ReserveCASignerPreparation stores the first generated CSR and exact event
// bytes before publishing. Concurrent replicas can compute different ECDSA CSR
// signatures, but only the first committed receipt may be returned or emitted.
func (s *Store) ReserveCASignerPreparation(ctx context.Context, p CASignerPreparation) (CASignerPreparation, error) {
	if p.TenantID == "" || p.CeremonyID == "" || p.Handle == "" || p.IssuerSHA256 == "" ||
		p.Purpose == "" || p.CSRPEM == "" || p.EventID == "" || p.EventTime.IsZero() ||
		len(p.EventActor) == 0 || len(p.EventPayload) == 0 {
		return CASignerPreparation{}, errors.New("store: CA signer preparation is incomplete")
	}
	hash := crypto.SHA256Hex([]byte(p.Handle))
	var out CASignerPreparation
	err := s.WithTenant(ctx, p.TenantID, func(tx pgx.Tx) error {
		if err := lockLiveTenantRegistrationTx(ctx, tx, p.TenantID); err != nil {
			return err
		}
		if err := setCASignerClaimScopeTx(ctx, tx); err != nil {
			return err
		}
		var parentID *string
		if p.ParentID != "" {
			parentID = &p.ParentID
		}
		_, err := tx.Exec(ctx, `UPDATE ca_signer_handle_claims SET
		        preparation_issuer_sha256 = $5, preparation_parent_id = $6,
		        preparation_purpose = $7, preparation_csr_pem = $8,
		        preparation_event_id = $9, preparation_event_time = $10,
		        preparation_event_actor = $11, preparation_event_payload = $12, preparation_status = 'pending'
		 WHERE tenant_id = $1 AND handle_sha256 = $2
		   AND owner_tenant_id = $3 AND owner_ceremony_id = $4
		   AND state = 'claimed' AND preparation_status IS NULL`,
			caSignerClaimPartition, hash, p.TenantID, p.CeremonyID,
			p.IssuerSHA256, parentID, p.Purpose, p.CSRPEM, p.EventID, p.EventTime,
			p.EventActor, p.EventPayload)
		if err != nil {
			return fmt.Errorf("store: reserve CA signer preparation: %w", err)
		}
		out, err = readCASignerPreparationTx(ctx, tx, p.TenantID, p.CeremonyID, hash)
		if err != nil {
			return err
		}
		if out.IssuerSHA256 != p.IssuerSHA256 || out.ParentID != p.ParentID || out.Purpose != p.Purpose || out.EventID != p.EventID {
			return ErrCASignerHandleClaimed
		}
		return nil
	})
	if err == nil {
		out.Handle = p.Handle
	}
	return out, err
}

func readCASignerPreparationTx(ctx context.Context, tx pgx.Tx, tenantID, ceremonyID, handleHash string) (CASignerPreparation, error) {
	var out CASignerPreparation
	var parentID *string
	err := tx.QueryRow(ctx, `SELECT preparation_issuer_sha256, preparation_parent_id, preparation_purpose,
	       preparation_csr_pem, preparation_event_id, preparation_event_time,
	       preparation_event_actor, preparation_event_payload, preparation_status
	  FROM ca_signer_handle_claims
	 WHERE tenant_id = $1 AND handle_sha256 = $2
	   AND owner_tenant_id = $3 AND owner_ceremony_id = $4
	   AND state = 'claimed' AND preparation_status IS NOT NULL`,
		caSignerClaimPartition, handleHash, tenantID, ceremonyID).Scan(
		&out.IssuerSHA256, &parentID, &out.Purpose, &out.CSRPEM, &out.EventID,
		&out.EventTime, &out.EventActor, &out.EventPayload, &out.Status)
	if err != nil {
		return CASignerPreparation{}, err
	}
	out.TenantID, out.CeremonyID = tenantID, ceremonyID
	if parentID != nil {
		out.ParentID = *parentID
	}
	return out, nil
}

// GetCASignerPreparation reads only this tenant's already-reserved public CSR.
// It never generates a key or changes event state on a GET.
func (s *Store) GetCASignerPreparation(ctx context.Context, tenantID, ceremonyID, handle string) (CASignerPreparation, error) {
	var out CASignerPreparation
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := setCASignerClaimScopeTx(ctx, tx); err != nil {
			return err
		}
		var err error
		out, err = readCASignerPreparationTx(ctx, tx, tenantID, ceremonyID, crypto.SHA256Hex([]byte(handle)))
		return err
	})
	if err == nil {
		out.Handle = handle
	}
	return out, err
}

func (s *Store) CompleteCASignerPreparation(ctx context.Context, p CASignerPreparation) error {
	return s.WithTenant(ctx, p.TenantID, func(tx pgx.Tx) error {
		if err := setCASignerClaimScopeTx(ctx, tx); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE ca_signer_handle_claims
		    SET preparation_status = 'completed'
		  WHERE tenant_id = $1 AND handle_sha256 = $2
		    AND owner_tenant_id = $3 AND owner_ceremony_id = $4
		    AND preparation_event_id = $5 AND preparation_event_time = $6
		    AND preparation_event_payload = $7
		    AND preparation_status IN ('pending', 'completed')`,
			caSignerClaimPartition, crypto.SHA256Hex([]byte(p.Handle)), p.TenantID,
			p.CeremonyID, p.EventID, p.EventTime, p.EventPayload)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrCASignerHandleClaimed
		}
		return nil
	})
}

// RetireCASignerHandleClaimsTx scrubs customer ownership during offboard while
// retaining only digests as permanent denial tombstones. This runs under the
// offboard transaction's lifecycle fence, so no concurrent claim can race it.
func RetireCASignerHandleClaimsTx(ctx context.Context, tx pgx.Tx, tenantID string) (int64, error) {
	if tenantID == "" || tenantID == caSignerClaimPartition {
		return 0, errors.New("store: CA signer claim retirement requires customer tenant")
	}
	var priorTenant, priorSearchPath string
	if err := tx.QueryRow(ctx, `SELECT current_setting('trstctl.tenant_id'), current_setting('search_path')`).Scan(&priorTenant, &priorSearchPath); err != nil {
		return 0, err
	}
	if priorTenant != tenantID {
		return 0, errors.New("store: CA signer claim retirement tenant scope changed")
	}
	if err := setCASignerClaimScopeTx(ctx, tx); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `UPDATE ca_signer_handle_claims
		   SET owner_tenant_id = NULL, owner_ceremony_id = NULL, state = 'retired',
		       preparation_issuer_sha256 = NULL, preparation_purpose = NULL,
		       preparation_parent_id = NULL,
		       preparation_csr_pem = NULL, preparation_event_id = NULL,
		       preparation_event_time = NULL, preparation_event_actor = NULL,
		       preparation_event_payload = NULL, preparation_status = NULL
		 WHERE tenant_id = $1 AND owner_tenant_id = $2 AND state = 'claimed'`,
		caSignerClaimPartition, tenantID)
	if err != nil {
		return 0, fmt.Errorf("store: retire CA signer claims: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id',$1,true), set_config('search_path',$2,true)`, priorTenant, priorSearchPath); err != nil {
		return 0, fmt.Errorf("store: restore tenant scope after CA signer claim retirement: %w", err)
	}
	return tag.RowsAffected(), nil
}
