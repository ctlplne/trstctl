// SPDX-License-Identifier: BUSL-1.1

// Package workloadchannel adapts the agent channel's client to the host
// Workload API's Upstream (epic B3).
//
// internal/agent/workloadapi holds an interface so it can be exercised without
// a control plane; this package is the translation, and the only place the two
// meet, which keeps the question "what does this host send upward on a
// workload's behalf" answerable by reading one file. The agent binary serves
// its --workload-api-socket through it, and the served conformance proof
// (B8-L2) drives the same code against a real control plane.
package workloadchannel

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/agent/workloadapi"
)

// Upstream sends a workload's public key and the selectors the host observed
// up the agent channel, and returns what the control plane issued.
type Upstream struct {
	c *transport.AgentClient
}

// New returns the Upstream for an agent channel client.
func New(c *transport.AgentClient) Upstream { return Upstream{c: c} }

// FetchWorkloadSVID implements workloadapi.Upstream.
func (w Upstream) FetchWorkloadSVID(
	ctx context.Context, publicKeyDER []byte, selectors, audience []string,
) (*workloadapi.SVIDSet, error) {
	resp, err := w.c.FetchWorkloadSVID(ctx, &transport.FetchWorkloadSVIDRequest{
		PublicKeyDER: publicKeyDER, Selectors: selectors, Audience: audience,
	})
	if err != nil {
		return nil, err
	}
	out := &workloadapi.SVIDSet{Bundle: resp.Bundle}
	for _, svid := range resp.X509SVIDs {
		out.X509 = append(out.X509, workloadapi.X509SVID{
			SPIFFEID: svid.SPIFFEID, CertChainDER: svid.CertChainDER, Hint: svid.Hint,
			ExpiresAt: unixOrZero(svid.ExpiresAtUnix),
		})
	}
	for _, svid := range resp.JWTSVIDs {
		out.JWT = append(out.JWT, workloadapi.JWTSVID{
			SPIFFEID: svid.SPIFFEID, Token: svid.Token,
			ExpiresAt: unixOrZero(svid.ExpiresAtUnix),
		})
	}
	return out, nil
}

// unixOrZero converts a unix timestamp, leaving zero as the zero time.
//
// Zero means the control plane did not report an expiry, which is different from
// "expires at the epoch" — and a client that read the epoch would treat a
// perfectly good SVID as long expired.
func unixOrZero(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}
