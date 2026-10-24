// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

// Compromised subject keys (owner decision, batch 11; CA/B BR 6.1.1.3,
// condition 4). Each certificate revoked for keyCompromise records its
// SubjectPublicKeyInfo SHA-256 once, when the revocation is projected, so
// issuance asks one indexed question per request — has this tenant recorded
// this key as compromised? — however many revocations the tenant has.

// recordCompromisedSubjectKeyTx records the subject key of a certificate the
// caller has just projected as revoked for keyCompromise. A certificate with
// no retained DER, or DER that does not parse, carries no key to record. The
// row is insert-only: a key once compromised stays compromised.
func (s *Store) recordCompromisedSubjectKeyTx(ctx context.Context, tx pgx.Tx, tenantID, fingerprint string, at time.Time) error {
	var der []byte
	err := tx.QueryRow(ctx, `SELECT certificate_der FROM certificates WHERE tenant_id = $1 AND fingerprint = $2`,
		tenantID, fingerprint).Scan(&der)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	spki, ok := certificateSPKISHA256(der)
	if !ok {
		return nil
	}
	return insertCompromisedSubjectKeyTx(ctx, tx, tenantID, fingerprint, spki, at)
}

func insertCompromisedSubjectKeyTx(ctx context.Context, tx pgx.Tx, tenantID, fingerprint, spkiSHA256 string, at time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO compromised_subject_keys (tenant_id, certificate_fingerprint, spki_sha256, revoked_at)
		VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id, certificate_fingerprint) DO NOTHING`,
		tenantID, fingerprint, spkiSHA256, at.UTC())
	return err
}

func certificateSPKISHA256(der []byte) (string, bool) {
	if len(der) == 0 {
		return "", false
	}
	info, err := certinfo.Inspect(der)
	if err != nil || len(info.SPKISHA256) != 64 {
		return "", false
	}
	return strings.ToLower(info.SPKISHA256), true
}

// CompromisedSubjectKey answers whether the tenant has recorded the subject
// key with this SPKI SHA-256 (lowercase hex) as compromised, naming the
// earliest certificate revoked for keyCompromise that carried it. It is one
// lookup on the (tenant_id, spki_sha256) index inside the tenant's RLS scope
// (AN-1), with no bound on how many revocations the tenant records.
func (s *Store) CompromisedSubjectKey(ctx context.Context, tenantID, spkiSHA256 string) (string, bool, error) {
	var fingerprint string
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT certificate_fingerprint FROM compromised_subject_keys
			WHERE tenant_id = $1 AND spki_sha256 = $2
			ORDER BY revoked_at, certificate_fingerprint LIMIT 1`, tenantID, strings.ToLower(spkiSHA256)).Scan(&fingerprint)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return fingerprint, true, nil
}

// compromisedKeyBackfillBatch bounds one backfill read.
const compromisedKeyBackfillBatch = 1000

// BackfillCompromisedSubjectKeys records the subject keys of certificates a
// build without the recording projection revoked for keyCompromise. It runs
// at startup before issuance is served, reads in bounded keyset batches, and
// is idempotent: a recorded certificate is skipped. It returns how many keys
// it recorded and how many revoked certificates had no readable key.
func (s *Store) BackfillCompromisedSubjectKeys(ctx context.Context) (recorded, unreadable int, err error) {
	type pending struct {
		tenantID, fingerprint string
		der                   []byte
		revokedAt             time.Time
	}
	afterTenant, afterFingerprint := ZeroUUID, ""
	for {
		var batch []pending
		rows, err := s.pool.Query(ctx,
			//trstctl:system-query — cross-tenant startup backfill reads keyCompromise-revoked certificates in bounded keyset batches by design; each recorded key is written back under its owning tenant's RLS context.
			`SELECT c.tenant_id::text, c.fingerprint, c.certificate_der, COALESCE(c.revoked_at, c.created_at)
			   FROM certificates c
			  WHERE c.revocation_reason = $1
			    AND (c.tenant_id, c.fingerprint) > ($2::uuid, $3)
			    AND NOT EXISTS (SELECT 1 FROM compromised_subject_keys k
			                     WHERE k.tenant_id = c.tenant_id AND k.certificate_fingerprint = c.fingerprint)
			  ORDER BY c.tenant_id, c.fingerprint
			  LIMIT $4`,
			string(crypto.RevocationReasonKeyCompromise), afterTenant, afterFingerprint, compromisedKeyBackfillBatch)
		if err != nil {
			return recorded, unreadable, fmt.Errorf("store: read keyCompromise revocations to backfill: %w", err)
		}
		for rows.Next() {
			var p pending
			if err := rows.Scan(&p.tenantID, &p.fingerprint, &p.der, &p.revokedAt); err != nil {
				rows.Close()
				return recorded, unreadable, err
			}
			batch = append(batch, p)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return recorded, unreadable, err
		}
		if len(batch) == 0 {
			return recorded, unreadable, nil
		}
		for start := 0; start < len(batch); {
			end := start
			for end < len(batch) && batch[end].tenantID == batch[start].tenantID {
				end++
			}
			group := batch[start:end]
			if err := s.WithTenant(ctx, group[0].tenantID, func(tx pgx.Tx) error {
				for _, p := range group {
					spki, ok := certificateSPKISHA256(p.der)
					if !ok {
						unreadable++
						continue
					}
					if err := insertCompromisedSubjectKeyTx(ctx, tx, p.tenantID, p.fingerprint, spki, p.revokedAt); err != nil {
						return err
					}
					recorded++
				}
				return nil
			}); err != nil {
				return recorded, unreadable, fmt.Errorf("store: record backfilled compromised subject keys: %w", err)
			}
			start = end
		}
		last := batch[len(batch)-1]
		afterTenant, afterFingerprint = last.tenantID, last.fingerprint
	}
}
