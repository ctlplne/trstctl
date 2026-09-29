// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/agent/enroll"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/store"
)

// enrollAuthority adapts the agent-enrollment authority to the API's minimal
// interfaces (api.BootstrapTokenIssuer + api.BootstrapEnroller), translating the
// enroll package's sentinel into the API's so the api package never imports the
// enrollment transport stack. Tokens are tenant-bound at mint and redeemed
// single-use through the durable store (WIRE-003). The authority's CA is
// in-process today (see internal/agent/enroll); custodying its key in the signer
// (AN-4) is a follow-up (WIRE-004/EXC-WIRE).
type enrollAuthority struct {
	a *enroll.Authority
	// peerCheck applies the agent channel's revocation and offboarding checks to
	// the HTTP renewal listener (F269). It must be set wherever renewal is served.
	peerCheck func(context.Context, mtls.PeerCertInfo) error
}

func (e enrollAuthority) IssueBootstrapToken(
	ctx context.Context,
	tenantID, allowedIdentity string,
) ([]byte, error) {
	return e.a.IssueBootstrapToken(ctx, tenantID, allowedIdentity)
}

func (e enrollAuthority) IssueBootstrapTokenWithRoles(
	ctx context.Context,
	tenantID, allowedIdentity string,
	roles []string,
) ([]byte, error) {
	return e.a.IssueBootstrapTokenWithRoles(ctx, tenantID, allowedIdentity, roles)
}

func (e enrollAuthority) EnrollBootstrap(ctx context.Context, token []byte, csrDER []byte) ([]byte, error) {
	chain, err := e.a.EnrollBootstrap(ctx, token, csrDER)
	if errors.Is(err, enroll.ErrBadToken) {
		return nil, fmt.Errorf("%w", api.ErrInvalidBootstrapToken)
	}
	return chain, err
}

func (e enrollAuthority) EnrollRenewal(ctx context.Context, peerCertsDER [][]byte, csrDER []byte) ([]byte, error) {
	if len(peerCertsDER) == 0 || len(peerCertsDER[0]) == 0 {
		return nil, fmt.Errorf("%w", api.ErrUnauthenticatedAgentRenewal)
	}
	info, err := mtls.PeerCertInfoFromDER(peerCertsDER[0])
	if err != nil {
		return nil, fmt.Errorf("%w", api.ErrUnauthenticatedAgentRenewal)
	}
	// A revoked certificate or an offboarded agent must not mint itself a fresh,
	// unrevoked identity (F269). Fail closed when the check is not wired.
	if e.peerCheck == nil {
		return nil, fmt.Errorf("%w: agent revocation checks are not configured", api.ErrAgentRenewalRefused)
	}
	if err := e.peerCheck(ctx, info); err != nil {
		return nil, err
	}
	chain, err := e.a.EnrollRenewal(ctx, peerCertsDER, csrDER)
	if errors.Is(err, enroll.ErrRenewalIdentityChange) {
		return nil, fmt.Errorf("%w: %s", api.ErrAgentRenewalRefused, strings.TrimPrefix(err.Error(), enroll.ErrRenewalIdentityChange.Error()+": "))
	}
	if errors.Is(err, enroll.ErrUnauthenticatedRenewal) {
		return nil, fmt.Errorf("%w", api.ErrUnauthenticatedAgentRenewal)
	}
	return chain, err
}

// agentRenewalPeerCheck refuses renewal for a revoked agent certificate or an
// offboarded agent, the same checks the agent channel applies to every RPC.
func agentRenewalPeerCheck(st *store.Store) func(context.Context, mtls.PeerCertInfo) error {
	return func(ctx context.Context, info mtls.PeerCertInfo) error {
		if st == nil {
			return fmt.Errorf("%w: agent revocation store is not configured", api.ErrAgentRenewalRefused)
		}
		agentID := agentRowID(info.TenantID, info.CommonName)
		revoked, err := st.AgentCertRevoked(ctx, info.TenantID, agentID, info.Serial, info.FingerprintSHA256)
		if err != nil {
			return fmt.Errorf("check agent certificate revocation: %w", err)
		}
		if revoked {
			return fmt.Errorf("%w: this agent certificate has been revoked", api.ErrAgentRenewalRefused)
		}
		offboarded, err := st.AgentOffboarded(ctx, info.TenantID, agentID)
		if err != nil {
			return fmt.Errorf("check agent offboarding: %w", err)
		}
		if offboarded {
			return fmt.Errorf("%w: this agent has been offboarded", api.ErrAgentRenewalRefused)
		}
		return nil
	}
}

func (e enrollAuthority) CABundlePEM() []byte { return e.a.CABundlePEM() }

// storeTokenStore adapts the PostgreSQL store to enroll.TokenStore, giving
// bootstrap tokens durable, tenant-scoped, single-use storage (WIRE-003): tokens
// survive restarts, redeem on any instance, and are tenant-attributed. The
// store's "no such row" on redemption (a missing, expired, or already-used token)
// maps to enroll.ErrBadToken so the transport returns a coarse 401.
type storeTokenStore struct{ st *store.Store }

var _ enroll.TokenRedemptionValidator = storeTokenStore{}

func (s storeTokenStore) Save(ctx context.Context, t enroll.MintedToken) error {
	_, err := s.st.CreateBootstrapToken(ctx, store.BootstrapTokenRecord{
		TenantID:        t.TenantID,
		TokenHash:       t.TokenHash,
		AllowedIdentity: t.AllowedIdentity,
		GrantedRoles:    t.Roles,
		ExpiresAt:       t.ExpiresAt,
	})
	return err
}

func (s storeTokenStore) Redeem(
	ctx context.Context,
	tokenHash string,
) (enroll.RedeemedToken, error) {
	rec, err := s.st.RedeemBootstrapToken(ctx, tokenHash)
	if err != nil {
		if store.IsNotFound(err) {
			return enroll.RedeemedToken{}, enroll.ErrBadToken
		}
		return enroll.RedeemedToken{}, err
	}
	return enroll.RedeemedToken{
		ID:              rec.ID,
		TenantID:        rec.TenantID,
		AllowedIdentity: rec.AllowedIdentity,
		Roles:           rec.GrantedRoles,
	}, nil
}

func (s storeTokenStore) ValidateRedemption(ctx context.Context, hash string, redeemed enroll.RedeemedToken) error {
	err := s.st.ValidateBootstrapTokenRedemption(ctx, redeemed.TenantID, redeemed.ID, hash)
	if store.IsNotFound(err) {
		return enroll.ErrBadToken
	}
	return err
}
