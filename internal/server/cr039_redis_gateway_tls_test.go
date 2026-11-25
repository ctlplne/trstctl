// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// A new session must fail at provider admission, before issuing a ticket that
// the gateway would later refuse to redeem.
func TestCR039RedisGatewayRejectsPlaintextProviderBeforeTicket(t *testing.T) {
	provider := &configuredDynamicProvider{cfg: config.DynamicSecretProviderConfig{Type: "redis", AllowPlaintextRedis: true}}
	ca, name, err := provider.DynamicSecretGatewayTLS(context.Background())
	if err == nil || len(ca) != 0 || name != "" {
		t.Fatalf("plaintext Redis provider authorized a gateway session: ca=%d name=%q err=%v", len(ca), name, err)
	}
}
