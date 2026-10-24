// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/store"
)

// compromisedKeyScanLimit bounds the keyCompromise revocations one issuance
// compares against. A tenant beyond it fails closed: the refusal says so.
const compromisedKeyScanLimit = 10000

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
// the store but no orchestrator.
func RefuseCompromisedSubjectKeyIn(ctx context.Context, st *store.Store, tenantID string, spkiDER []byte) error {
	if st == nil {
		return nil
	}
	if len(spkiDER) == 0 {
		return fmt.Errorf("orchestrator: no subject key to check")
	}
	revoked, err := st.KeyCompromiseRevokedCertificates(ctx, tenantID, compromisedKeyScanLimit+1)
	if err != nil {
		return fmt.Errorf("orchestrator: read the tenant's compromised keys: %w", err)
	}
	if len(revoked) > compromisedKeyScanLimit {
		return fmt.Errorf("%w: the tenant records more than %d keyCompromise revocations; the subject key could not be checked against all of them",
			crypto.ErrCompromisedKey, compromisedKeyScanLimit)
	}
	want := crypto.SHA256Hex(spkiDER)
	for _, der := range revoked {
		info, err := certinfo.Inspect(der)
		if err != nil {
			continue
		}
		if strings.EqualFold(info.SPKISHA256, want) {
			return fmt.Errorf("%w: certificate %s, revoked for keyCompromise, carried this key", crypto.ErrCompromisedKey, info.SHA256Fingerprint)
		}
	}
	return nil
}
