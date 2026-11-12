// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// CodeSigningKeyCertificate is a code-signing key's certificate chain attached
// through the API (P9-L1), the projection of codesign.certificate_attached.
type CodeSigningKeyCertificate struct {
	TenantID        string
	KeyID           string
	ChainDER        [][]byte // leaf first
	LeafFingerprint string
	NotAfter        time.Time
	AttachedBy      string
	AttachedAt      time.Time
}

// ApplyCodeSigningKeyCertificateAttachedTx keeps the newest attached chain of
// a key; an older event replayed after a newer one changes nothing.
func (s *Store) ApplyCodeSigningKeyCertificateAttachedTx(ctx context.Context, tx pgx.Tx, c CodeSigningKeyCertificate, eventSequence uint64) error {
	if c.TenantID == "" || c.KeyID == "" || len(c.ChainDER) == 0 || c.LeafFingerprint == "" {
		return errors.New("store: an attached code-signing chain needs its tenant, key, certificates and leaf fingerprint")
	}
	if eventSequence == 0 || eventSequence > 1<<62 {
		return fmt.Errorf("store: code-signing chain event sequence %d is out of range", eventSequence)
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO code_signing_key_certificates
		        (tenant_id, key_id, chain_der, leaf_fingerprint, not_after, attached_by, attached_at, event_sequence)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (tenant_id, key_id) DO UPDATE
		    SET chain_der = EXCLUDED.chain_der, leaf_fingerprint = EXCLUDED.leaf_fingerprint,
		        not_after = EXCLUDED.not_after, attached_by = EXCLUDED.attached_by,
		        attached_at = EXCLUDED.attached_at, event_sequence = EXCLUDED.event_sequence
		  WHERE code_signing_key_certificates.event_sequence < EXCLUDED.event_sequence`,
		c.TenantID, c.KeyID, c.ChainDER, c.LeafFingerprint, c.NotAfter, c.AttachedBy, c.AttachedAt, int64(eventSequence)) // #nosec G115 -- bounded above (CWE-190)
	return err
}

// GetCodeSigningKeyCertificate returns the chain attached to a key, or an
// error IsNotFound reports when none was.
func (s *Store) GetCodeSigningKeyCertificate(ctx context.Context, tenantID, keyID string) (CodeSigningKeyCertificate, error) {
	var out CodeSigningKeyCertificate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT tenant_id::text, key_id, chain_der, leaf_fingerprint, not_after, attached_by, attached_at
			   FROM code_signing_key_certificates WHERE tenant_id = $1 AND key_id = $2`, tenantID, keyID).Scan(
			&out.TenantID, &out.KeyID, &out.ChainDER, &out.LeafFingerprint, &out.NotAfter, &out.AttachedBy, &out.AttachedAt)
	})
	if err != nil {
		return CodeSigningKeyCertificate{}, err
	}
	return out, nil
}
