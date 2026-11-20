// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"context"
	"net"
	"slices"

	"trstctl.com/trstctl/internal/crypto/dbdsn"
	"trstctl.com/trstctl/internal/netsec"
)

type databaseDialFunc func(context.Context, string, string) (net.Conn, error)

func (g *Gateway) bindDatabaseDial(in SessionIntent) (databaseDialFunc, error) {
	route := in.DatabaseRoute
	if err := route.Validate(dbdsn.GatewayDriver(in.TargetType), in.explicitDatabaseTrust()); err != nil {
		return nil, err
	}
	policy := netsec.DatabaseDialOptions{OperatorFile: route.Source == dbdsn.OperatorFileSource, Agent: g.cfg.DatabaseEgress}
	for _, raw := range route.PrivateCIDRs {
		prefix, err := netsec.ParseEgressAllowPrefix(raw)
		if err != nil {
			return nil, dbdsn.ErrGatewayRoute
		}
		policy.PrivateCIDRs = append(policy.PrivateCIDRs, prefix)
	}
	dialer := netsec.NewDatabaseDialer(policy)
	for _, endpoint := range route.Hosts {
		if err := dialer.CheckEndpoint(endpoint); err != nil {
			return nil, dbdsn.ErrGatewayRoute
		}
	}
	return func(ctx context.Context, network, endpoint string) (net.Conn, error) {
		if !slices.Contains(route.Hosts, endpoint) {
			return nil, dbdsn.ErrGatewayRoute
		}
		return dialer.DialContext(ctx, network, endpoint)
	}, nil
}
