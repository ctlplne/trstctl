package server

import (
	"context"
	"errors"
	"fmt"

	"trstctl.com/trstctl/internal/agent/enroll"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/store"
)

// enrollAuthority adapts the agent-enrollment authority to the API's minimal
// interfaces (api.BootstrapTokenIssuer + api.BootstrapEnroller), translating the
// enroll package's sentinel into the API's so the api package never imports the
// enrollment transport stack. Tokens are tenant-bound at mint and redeemed
// single-use through the durable store (WIRE-003). The authority's CA is
// in-process today (see internal/agent/enroll); custodying its key in the signer
// (AN-4) is a follow-up (WIRE-004/EXC-WIRE).
type enrollAuthority struct{ a *enroll.Authority }

func (e enrollAuthority) IssueBootstrapToken(ctx context.Context, tenantID, allowedIdentity string) ([]byte, error) {
	token, err := e.a.IssueBootstrapToken(ctx, tenantID, allowedIdentity)
	if err != nil {
		return nil, err
	}
	return []byte(token), nil
}

func (e enrollAuthority) EnrollBootstrap(ctx context.Context, token []byte, csrDER []byte) ([]byte, error) {
	chain, err := e.a.EnrollBootstrap(ctx, string(token), csrDER)
	if errors.Is(err, enroll.ErrBadToken) {
		return nil, fmt.Errorf("%w", api.ErrInvalidBootstrapToken)
	}
	return chain, err
}

func (e enrollAuthority) CABundlePEM() []byte { return e.a.CABundlePEM() }

// storeTokenStore adapts the PostgreSQL store to enroll.TokenStore, giving
// bootstrap tokens durable, tenant-scoped, single-use storage (WIRE-003): tokens
// survive restarts, redeem on any instance, and are tenant-attributed. The
// store's "no such row" on redemption (a missing, expired, or already-used token)
// maps to enroll.ErrBadToken so the transport returns a coarse 401.
type storeTokenStore struct{ st *store.Store }

func (s storeTokenStore) Save(ctx context.Context, t enroll.MintedToken) error {
	_, err := s.st.CreateBootstrapToken(ctx, store.BootstrapTokenRecord{
		TenantID:        t.TenantID,
		TokenHash:       t.TokenHash,
		AllowedIdentity: t.AllowedIdentity,
		ExpiresAt:       t.ExpiresAt,
	})
	return err
}

func (s storeTokenStore) Redeem(ctx context.Context, tokenHash string) (enroll.RedeemedToken, error) {
	rec, err := s.st.RedeemBootstrapToken(ctx, tokenHash)
	if err != nil {
		if store.IsNotFound(err) {
			return enroll.RedeemedToken{}, enroll.ErrBadToken
		}
		return enroll.RedeemedToken{}, err
	}
	return enroll.RedeemedToken{TenantID: rec.TenantID, AllowedIdentity: rec.AllowedIdentity}, nil
}
