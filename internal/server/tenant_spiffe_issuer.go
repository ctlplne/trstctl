// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"time"

	"trstctl.com/trstctl/internal/protocols/spiffe"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenancy"
)

// The Workload API owns a long-lived socket. Recheck each signature so a stream
// opened while active cannot mint another SVID after suspension. Public trust
// bundles stay readable, including the data clients need to verify old leaves.
type tenantSPIFFEIssuer struct {
	spiffe.Issuer
	tenantID string
	check    tenancy.ServiceCheck
	work     tenancy.ServiceWork
	// store, when set, refuses a workload key the tenant recorded as
	// compromised (owner decision, batch 11).
	store *store.Store
}

func (i tenantSPIFFEIssuer) SignX509SVID(ctx context.Context, id string, pub []byte, ttl time.Duration) ([]byte, error) {
	ctx, release, err := i.work.Begin(ctx, i.tenantID)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := i.check.Check(ctx, i.tenantID); err != nil {
		return nil, err
	}
	if err := refuseCompromisedPublicKey(ctx, i.store, i.tenantID, pub); err != nil {
		return nil, err
	}
	return i.Issuer.SignX509SVID(ctx, id, pub, ttl)
}

// SignJWTSVIDWithClaims signs a JWT-SVID with extra claims (M4) under the same
// tenant service checks.
func (i tenantSPIFFEIssuer) SignJWTSVIDWithClaims(ctx context.Context, id string, audience []string, ttl time.Duration, extra map[string]any) (string, error) {
	signer, ok := i.Issuer.(interface {
		SignJWTSVIDWithClaims(context.Context, string, []string, time.Duration, map[string]any) (string, error)
	})
	if !ok {
		return "", errors.New("server: the SPIFFE issuer cannot sign JWT-SVIDs with extra claims")
	}
	ctx, release, err := i.work.Begin(ctx, i.tenantID)
	if err != nil {
		return "", err
	}
	defer release()
	if err := i.check.Check(ctx, i.tenantID); err != nil {
		return "", err
	}
	return signer.SignJWTSVIDWithClaims(ctx, id, audience, ttl, extra)
}

func (i tenantSPIFFEIssuer) SignJWTSVID(ctx context.Context, id string, audience []string, ttl time.Duration) (string, error) {
	ctx, release, err := i.work.Begin(ctx, i.tenantID)
	if err != nil {
		return "", err
	}
	defer release()
	if err := i.check.Check(ctx, i.tenantID); err != nil {
		return "", err
	}
	return i.Issuer.SignJWTSVID(ctx, id, audience, ttl)
}

// SignJWTAccessToken signs an RFC 9068 JWT access token (M4-L3) under the
// same tenant service checks.
func (i tenantSPIFFEIssuer) SignJWTAccessToken(ctx context.Context, id string, audience []string, ttl time.Duration, extra map[string]any) (string, error) {
	signer, ok := i.Issuer.(jwtAccessTokenSigner)
	if !ok {
		return "", errors.New("server: the SPIFFE issuer cannot sign JWT access tokens")
	}
	ctx, release, err := i.work.Begin(ctx, i.tenantID)
	if err != nil {
		return "", err
	}
	defer release()
	if err := i.check.Check(ctx, i.tenantID); err != nil {
		return "", err
	}
	return signer.SignJWTAccessToken(ctx, id, audience, ttl, extra)
}

// jwtAccessTokenSigner signs RFC 9068 JWT access tokens (M4-L3).
type jwtAccessTokenSigner interface {
	SignJWTAccessToken(context.Context, string, []string, time.Duration, map[string]any) (string, error)
}
