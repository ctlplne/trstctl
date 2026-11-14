// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/hex"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// acmeSharedState keeps one served ACME mount's nonces and finalize claims in
// PostgreSQL, where every control-plane replica sees them (P15-L7): a nonce is
// stored by its SHA-256 digest only, and a finalize claim names this process
// as its holder so it releases only its own.
type acmeSharedState struct {
	store     *store.Store
	tenantID  string
	holder    string
	maxNonces int
}

func newACMESharedState(st *store.Store, tenantID string, maxNonces int) acmeSharedState {
	b, _ := crypto.RandomBytes(16)
	return acmeSharedState{store: st, tenantID: tenantID, holder: hex.EncodeToString(b), maxNonces: maxNonces}
}

func (a acmeSharedState) MintNonce(ctx context.Context, nonce string, expires time.Time) error {
	return a.store.MintACMENonce(ctx, a.tenantID, crypto.SHA256Hex([]byte(nonce)), expires, a.maxNonces)
}

func (a acmeSharedState) RedeemNonce(ctx context.Context, nonce string) (bool, error) {
	return a.store.RedeemACMENonce(ctx, a.tenantID, crypto.SHA256Hex([]byte(nonce)))
}

func (a acmeSharedState) ClaimFinalize(ctx context.Context, orderID string, until time.Time) (bool, error) {
	return a.store.ClaimACMEFinalize(ctx, a.tenantID, orderID, a.holder, until)
}

func (a acmeSharedState) ReleaseFinalize(ctx context.Context, orderID string) error {
	return a.store.ReleaseACMEFinalize(ctx, a.tenantID, orderID, a.holder)
}
