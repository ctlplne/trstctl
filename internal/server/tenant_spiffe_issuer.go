// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/protocols/spiffe"
	"trstctl.com/trstctl/internal/tenancy"
)

// The Workload API owns a long-lived socket. Recheck each signature so a stream
// opened while active cannot mint another SVID after suspension. Public trust
// bundles stay readable, including the data clients need to verify old leaves.
type tenantSPIFFEIssuer struct {
	spiffe.Issuer
	tenantID string
	check    tenancy.ServiceCheck
}

func (i tenantSPIFFEIssuer) SignX509SVID(ctx context.Context, id string, pub []byte, ttl time.Duration) ([]byte, error) {
	if err := i.check.Check(ctx, i.tenantID); err != nil {
		return nil, err
	}
	return i.Issuer.SignX509SVID(ctx, id, pub, ttl)
}

func (i tenantSPIFFEIssuer) SignJWTSVID(ctx context.Context, id string, audience []string, ttl time.Duration) (string, error) {
	if err := i.check.Check(ctx, i.tenantID); err != nil {
		return "", err
	}
	return i.Issuer.SignJWTSVID(ctx, id, audience, ttl)
}
