// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"fmt"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// RefuseCompromisedSubjectKey refuses to certify a subject key the tenant has
// recorded as compromised: a certificate of the tenant revoked with reason
// keyCompromise (directly, or by the key-compromise flow once its revocation
// is recorded) carried the same SubjectPublicKeyInfo (owner decision, batch
// 11; CA/B BR 6.1.1.3, condition 4). The comparison stays inside the tenant
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
		return fmt.Errorf("%w: certificate %s, revoked for keyCompromise, carried this key", crypto.ErrCompromisedKey, fingerprint)
	}
	return nil
}
