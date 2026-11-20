// SPDX-License-Identifier: BUSL-1.1

package transport

import (
	"context"
	"strings"

	"google.golang.org/grpc/metadata"
	"trstctl.com/trstctl/internal/protocol"
)

const guardedDatabaseRedemption = "guarded-database-redemption-v1"

type guardedDatabaseRedemptionKey struct{}

// WithGuardedDatabaseRedemption is attached after this gateway job's bound
// route and its socket guard are ready. It affects only the redemption call.
func WithGuardedDatabaseRedemption(ctx context.Context) context.Context {
	return context.WithValue(ctx, guardedDatabaseRedemptionKey{}, true)
}

// HasGuardedDatabaseRedemption reads the current authenticated RPC metadata.
func HasGuardedDatabaseRedemption(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	values := md.Get(protocol.MetadataAgentCapabilities)
	if len(values) != 1 {
		return false
	}
	for _, capability := range strings.Split(values[0], ",") {
		if capability == guardedDatabaseRedemption {
			return true
		}
	}
	return false
}
