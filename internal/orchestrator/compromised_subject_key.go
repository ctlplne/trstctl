// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// RefuseCompromisedSubjectKey refuses to certify a subject key the tenant has
// recorded as compromised: a certificate of the tenant revoked with reason
// keyCompromise, or whose identity or queued revocation reported that reason,
// carried the same SubjectPublicKeyInfo (owner decisions, batches 11 and 14;
// CA/B BR 6.1.1.3, condition 4). The comparison stays inside the tenant
// (AN-1). The refusal wraps crypto.ErrCompromisedKey.
func (o *Orchestrator) RefuseCompromisedSubjectKey(ctx context.Context, tenantID string, spkiDER []byte) error {
	if o == nil {
		return nil
	}
	return RefuseCompromisedSubjectKeyIn(ctx, o.store, tenantID, spkiDER)
}

// RefuseCompromisedSubjectKeyIn is the same refusal for a caller that holds
// the store but no orchestrator. The revocation projection records each
// keyCompromise revocation's SPKI SHA-256, so this is one indexed lookup by
// tenant and hash however many revocations the tenant has; a mass
// key-compromise revocation never blocks the replacement issuance it needs.
func RefuseCompromisedSubjectKeyIn(ctx context.Context, st *store.Store, tenantID string, spkiDER []byte) error {
	if st == nil {
		return nil
	}
	if len(spkiDER) == 0 {
		return fmt.Errorf("orchestrator: no subject key to check")
	}
	fingerprint, compromised, err := st.CompromisedSubjectKey(ctx, tenantID, crypto.SHA256Hex(spkiDER))
	if err != nil {
		return fmt.Errorf("orchestrator: read the tenant's compromised keys: %w", err)
	}
	if compromised {
		return fmt.Errorf("%w: certificate %s carried this key and is revoked, or being revoked, for keyCompromise", crypto.ErrCompromisedKey, fingerprint)
	}
	return nil
}

// recordCompromisedSubjectKeysTx runs in the transaction that revokes an
// identity for keyCompromise (owner decision, batch 14). It records the
// subject key of every certificate that revocation will revoke, so issuance
// refuses the key from the compromise report on, not only once
// revocation.publish delivers and the certificates' own revocations project
// (which record the same keys again, converging on these rows). One event per
// certificate, with an ID derived from the tenant, identity and certificate,
// so a retried command appends nothing twice. A crash between the
// revocation's append and these leaves the publish's record as the backstop.
func (o *Orchestrator) recordCompromisedSubjectKeysTx(ctx context.Context, tx pgx.Tx, tenantID, identityID string, at time.Time) error {
	keys, err := o.store.IdentityRevocationSubjectKeysTx(ctx, tx, tenantID, identityID)
	if err != nil {
		return err
	}
	for _, key := range keys {
		record := projections.CertificateSubjectKeyCompromised{
			IdentityID: identityID, Fingerprint: key.Fingerprint, SPKISHA256: key.SPKISHA256,
		}
		if err := projections.ValidateCertificateSubjectKeyCompromised(record); err != nil {
			return err
		}
		payload, err := json.Marshal(record)
		if err != nil {
			return err
		}
		next := events.Event{
			ID:   projections.CertificateSubjectKeyCompromisedEventID(tenantID, identityID, key.Fingerprint),
			Type: projections.EventCertificateSubjectKeyCompromised, TenantID: tenantID, Time: at, Data: payload,
		}
		// The append's duplicate window is finite; a retry after it reuses the
		// retained event instead of appending a second one with the same ID.
		ev, found, err := o.log.EventByID(ctx, next.ID)
		if err != nil {
			return err
		}
		if !found {
			if ev, err = o.log.Append(ctx, next); err != nil {
				return err
			}
		}
		if ev.ID != next.ID || ev.Type != next.Type || ev.TenantID != tenantID || !bytes.Equal(ev.Data, payload) {
			return fmt.Errorf("%w: canonical compromised subject key event differs", store.ErrIdempotencyConflict)
		}
		if err := o.proj.ApplyTx(ctx, tx, ev); err != nil {
			return err
		}
	}
	return nil
}
