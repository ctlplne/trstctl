// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// A rebuilt read model may repair an outbox intent whose original row was
// reclaimed after delivery. Keep pending work unless a later, CA-signed full
// CRL proves the exact issuance or revocation effect already happened. The map
// is scoped to one pinned event-history replay and one SQL transaction.
type crlPublicationReplay struct {
	baselineID int64
	sources    map[string]crlPublicationSource
	published  map[string][]crlPublicationProof
}

type crlPublicationSource struct {
	tenantID string
	caID     string
	sequence uint64
	serials  []string // empty for first publication after issuance
}

type crlPublicationProof struct {
	sequence uint64
	at       time.Time
	crl      CRLPublished
}

func newCRLPublicationReplay(ctx context.Context, tx pgx.Tx) (*crlPublicationReplay, error) {
	r := &crlPublicationReplay{
		sources:   make(map[string]crlPublicationSource),
		published: make(map[string][]crlPublicationProof),
	}
	if err := tx.QueryRow(ctx,
		//trstctl:system-query — an owner-role rebuild captures the global outbox high-water mark before replaying all tenants; later cleanup still filters by tenant_id.
		`SELECT COALESCE(MAX(id), 0) FROM outbox`).Scan(&r.baselineID); err != nil {
		return nil, fmt.Errorf("projections: capture outbox replay boundary: %w", err)
	}
	return r, nil
}

func crlPublicationKey(tenantID, eventID, caID string) string {
	return tenantID + "\x1f" + eventID + "\x1f" + caID
}

func crlAuthorityKey(tenantID, caID string) string {
	return tenantID + "\x1f" + caID
}

func (r *crlPublicationReplay) observe(e events.Event) error {
	switch e.Type {
	case EventCAEndEntityIssued:
		var issued struct {
			CAID string `json:"ca_id"`
		}
		if err := json.Unmarshal(e.Data, &issued); err != nil {
			return fmt.Errorf("projections: decode CRL issuance source: %w", err)
		}
		if issued.CAID != "" {
			r.sources[crlPublicationKey(e.TenantID, e.ID, issued.CAID)] = crlPublicationSource{
				tenantID: e.TenantID, caID: issued.CAID, sequence: e.Sequence,
			}
		}
	case EventCertificateRevocationBatchApplied:
		var batch CertificateRevocationBatchApplied
		if err := json.Unmarshal(e.Data, &batch); err != nil {
			return fmt.Errorf("projections: decode CRL revocation source: %w", err)
		}
		for _, item := range batch.Items {
			if item.Status != "revoked" {
				continue
			}
			key := crlPublicationKey(e.TenantID, e.ID, item.CAID)
			source := r.sources[key]
			source.tenantID, source.caID, source.sequence = e.TenantID, item.CAID, e.Sequence
			source.serials = append(source.serials, item.Serial)
			r.sources[key] = source
		}
	case EventCRLPublished:
		var published CRLPublished
		if err := json.Unmarshal(e.Data, &published); err != nil {
			return fmt.Errorf("projections: decode CRL publication proof: %w", err)
		}
		if published.CAID != "" && len(published.DER) != 0 &&
			(published.Kind == "" || published.Kind == "full") && published.DeltaBaseNumber == nil && published.ShardIndex == 0 {
			key := crlAuthorityKey(e.TenantID, published.CAID)
			r.published[key] = append(r.published[key], crlPublicationProof{
				sequence: e.Sequence, at: e.Time, crl: published,
			})
		}
	}
	return nil
}

type rebuiltCRLCommand struct {
	id       int64
	tenantID string
	key      string
	payload  []byte
}

func (r *crlPublicationReplay) discardProvenCompleted(ctx context.Context, st *store.Store, tx pgx.Tx) error {
	rows, err := tx.Query(ctx,
		//trstctl:system-query — only this transaction's freshly rebuilt pending CRL commands are examined across tenants; each deletion below is tenant-scoped.
		`SELECT id, tenant_id::text, idempotency_key, payload FROM outbox
		 WHERE id > $1 AND destination = $2 AND status = 'pending' AND attempts = 0
		 ORDER BY id`, r.baselineID, store.CertificateCRLPublicationDestination)
	if err != nil {
		return fmt.Errorf("projections: inspect rebuilt CRL commands: %w", err)
	}
	var commands []rebuiltCRLCommand
	for rows.Next() {
		var command rebuiltCRLCommand
		if err := rows.Scan(&command.id, &command.tenantID, &command.key, &command.payload); err != nil {
			rows.Close()
			return err
		}
		commands = append(commands, command)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, command := range commands {
		var payload store.CertificateCRLPublication
		if err := json.Unmarshal(command.payload, &payload); err != nil {
			return fmt.Errorf("projections: invalid rebuilt CRL command: %w", err)
		}
		if command.key != store.CertificateCRLPublicationDestination+":"+payload.EventID+":"+payload.CAID {
			return fmt.Errorf("projections: rebuilt CRL command has a mismatched idempotency key")
		}
		source, found := r.sources[crlPublicationKey(command.tenantID, payload.EventID, payload.CAID)]
		if !found {
			continue // No retained source proof: leave the new pending intent intact.
		}
		caPEM, err := st.CAAuthorityCertificateTx(ctx, tx, command.tenantID, source.caID)
		if errors.Is(err, pgx.ErrNoRows) {
			continue // No replayable CA trust anchor: keep the pending command.
		}
		if err != nil {
			return fmt.Errorf("projections: read CRL issuer for replay: %w", err)
		}
		issuerDER, err := certinfo.LeafDER(caPEM)
		if err != nil {
			return fmt.Errorf("projections: decode CRL issuer for replay: %w", err)
		}
		completed := false
		for _, proof := range r.published[crlAuthorityKey(command.tenantID, source.caID)] {
			if proof.sequence <= source.sequence {
				continue
			}
			info, err := crypto.ParseCRL(proof.crl.DER, issuerDER)
			if err != nil || info.Number != proof.crl.Number ||
				!info.ThisUpdate.Equal(proof.crl.ThisUpdate.Truncate(time.Second)) ||
				!info.NextUpdate.Equal(proof.crl.NextUpdate.Truncate(time.Second)) ||
				!info.NextUpdate.After(info.ThisUpdate) || proof.at.After(info.NextUpdate) {
				continue
			}
			contained := make(map[string]bool, len(info.RevokedSerials))
			for _, serial := range info.RevokedSerials {
				contained[strings.ToLower(serial)] = true
			}
			completed = true
			for _, serial := range source.serials {
				if !contained[strings.ToLower(serial)] {
					completed = false
					break
				}
			}
			if completed {
				break
			}
		}
		if !completed {
			continue
		}
		tag, err := tx.Exec(ctx, `DELETE FROM outbox
			WHERE tenant_id = $1 AND id = $2 AND destination = $3 AND idempotency_key = $4
			  AND status = 'pending' AND attempts = 0`,
			command.tenantID, command.id, store.CertificateCRLPublicationDestination, command.key)
		if err != nil {
			return fmt.Errorf("projections: discard proven completed CRL command: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("projections: proven completed CRL command changed before removal")
		}
	}
	return nil
}
