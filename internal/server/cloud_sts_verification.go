// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
	"net/netip"
	"time"
	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
	"trstctl.com/trstctl/internal/crypto/awssignin"
)

func (p *configuredDynamicProvider) verifySTSLeaseCredential(ctx context.Context, credential []byte) (string, error) {
	endpoint := awsiam.STSEndpoint(p.cfg.Region, p.cfg.Endpoint)
	if p.guard != nil {
		if err := p.guard.CheckURL(endpoint); err != nil {
			return "", err
		}
	}
	prefixes := make([]netip.Prefix, 0, len(p.cfg.PrivateEgressCIDRs))
	for _, raw := range p.cfg.PrivateEgressCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return "", errors.New("server: invalid STS verification egress prefix")
		}
		prefixes = append(prefixes, prefix)
	}
	roles := make([]string, 0, len(p.allowedRoles))
	for role, allowed := range p.allowedRoles {
		if allowed {
			roles = append(roles, p.cfg.RoleBindings[role])
		}
	}
	_, err := awsiam.VerifyAssumedRole(ctx, awsiam.Config{Endpoint: endpoint, Region: p.cfg.Region, AllowInsecureLoopback: p.cfg.AllowInsecureLoopback, PrivateEgressCIDRs: prefixes, UseCredentials: func(ctx context.Context, use func(awssignin.Credentials) error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return awsiam.UseLeaseCredential(credential, time.Now(), use)
	}}, roles)
	if err != nil {
		return "", err
	}
	return "authenticated", nil
}
