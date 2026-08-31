// SPDX-License-Identifier: MPL-2.0

package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
)

// BrokerCertificateStates is the canonical operator-state vocabulary. SQL derives
// it once for both filtering and display; clients must not recalculate it.
func BrokerCertificateStates() []string {
	return []string{"valid", "not_yet_valid", "expired", "revoked", "superseded", "unknown"}
}

const brokerCertificateStateExpression = `CASE
	WHEN status = 'revoked' THEN 'revoked'
	WHEN status = 'superseded' THEN 'superseded'
	WHEN status <> 'active' OR not_before IS NULL OR not_after IS NULL OR not_after <= not_before THEN 'unknown'
	WHEN not_after <= $now THEN 'expired'
	WHEN not_before > $now THEN 'not_yet_valid'
	ELSE 'valid' END`

// Only internal positional placeholders are supplied, never request text.
func brokerCertificateStateSQL(timeParameter string) string {
	return strings.ReplaceAll(brokerCertificateStateExpression, "$now", timeParameter)
}

// BrokerCertificate deliberately omits proof, public certificate bodies and
// recovery keys/bindings. It joins original issuance facts to the SAME inventory
// row that revocation, ownership and discovery already use.
type BrokerCertificate struct {
	CertificateID      string
	Fingerprint        string
	CertificateSubject string
	SPIFFEID           string
	Serial             string
	CurrentOwnerID     *string
	NotBefore          *time.Time
	NotAfter           *time.Time
	RecordedAt         time.Time
	Status             string
	State              string
	Issuance           *BrokerIssuance
}

type BrokerHistoryFilter struct {
	AfterTime *time.Time
	AfterID   string
	Limit     int
	Query     string
	Method    string
	State     string
}

const brokerHistoryColumns = `id::text, fingerprint, subject, serial, owner_id::text,
	not_before, not_after, created_at, status, broker_issuance, certificate_der`

func scanBrokerCertificate(row pgx.Row, item *BrokerCertificate) error {
	var certificateDER []byte
	if err := row.Scan(&item.CertificateID, &item.Fingerprint, &item.CertificateSubject, &item.Serial,
		&item.CurrentOwnerID, &item.NotBefore, &item.NotAfter, &item.RecordedAt, &item.Status, &item.Issuance, &certificateDER, &item.State); err != nil {
		return err
	}
	item.SPIFFEID = ""
	// Extract from the exact fingerprint-bound public leaf, not its friendly
	// subject or mutable owner. Retained/erased/noncanonical history stays
	// readable without inventing a replacement identity. Do not return DER.
	if len(certificateDER) > 0 && crypto.SHA256Hex(certificateDER) == item.Fingerprint {
		if id, err := crypto.SPIFFEIDFromCert(certificateDER); err == nil {
			item.SPIFFEID = id
		}
	}
	return nil
}

// ListBrokerCertificatesPage uses a newest-first (recorded time, id) keyset, not
// offset pagination. An extra row tells the API whether another page really exists.
func (s *Store) ListBrokerCertificatesPage(ctx context.Context, tenantID string, f BrokerHistoryFilter, now time.Time) ([]BrokerCertificate, error) {
	if f.Limit < 1 || f.Limit > 101 {
		return nil, errors.New("store: broker history limit must be between 1 and 101")
	}
	items := []BrokerCertificate{}
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+brokerHistoryColumns+`, `+brokerCertificateStateSQL("$7")+`
			FROM certificates WHERE tenant_id = $1 AND issuance_idempotency_key LIKE 'broker-issue:%'
			  AND ($2::timestamptz IS NULL OR (created_at, id) < ($2, $3::uuid))
			  AND ($4::text = '' OR position(lower($4) in lower(concat_ws(' ', id::text, fingerprint, serial, subject,
			      broker_issuance->>'agent_id', broker_issuance->>'subject'))) > 0)
			  AND ($5::text = '' OR broker_issuance->>'method' = $5)
			  AND ($6::text = '' OR (`+brokerCertificateStateSQL("$7")+`) = $6)
			ORDER BY created_at DESC, id DESC LIMIT $8`,
			tenantID, f.AfterTime, f.AfterID, f.Query, f.Method, f.State, now, f.Limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item BrokerCertificate
			if err := scanBrokerCertificate(rows, &item); err != nil {
				return err
			}
			items = append(items, item)
		}
		return rows.Err()
	})
	return items, err
}

func (s *Store) GetBrokerCertificate(ctx context.Context, tenantID, id string, now time.Time) (BrokerCertificate, error) {
	var item BrokerCertificate
	err := s.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanBrokerCertificate(tx.QueryRow(ctx, `SELECT `+brokerHistoryColumns+`, `+brokerCertificateStateSQL("$3")+`
			FROM certificates WHERE tenant_id = $1 AND id = $2::uuid
			  AND issuance_idempotency_key LIKE 'broker-issue:%'`, tenantID, id, now), &item)
	})
	return item, err
}
