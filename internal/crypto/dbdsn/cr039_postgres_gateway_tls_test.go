// SPDX-License-Identifier: BUSL-1.1

package dbdsn

import (
	"errors"
	"testing"
)

func TestCR039PostgresGatewayRouteCannotAuthorizeDowngrade(t *testing.T) {
	target, err := Parse(Postgres, []byte("postgres://fixture:fixture@db.private.test/orders"), Gateway)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Wipe()
	mode, err := GatewayTLSMode(Postgres, target, false)
	if err != nil || mode != GatewayVerifiedTLS {
		t.Fatalf("gateway authorized PostgreSQL TLS downgrade: mode=%q err=%v", mode, err)
	}
	for _, insecure := range []string{GatewayPlain, GatewayPreferTLS} {
		route := GatewayRoute{Revision: GatewayRouteRevision, ProviderID: "pg-provider",
			Hosts: []string{"db.private.test:5432"}, Database: "orders", TLS: insecure, Source: OperatorFileSource}
		if err := route.Validate(Postgres, false); !errors.Is(err, ErrGatewayRoute) {
			t.Fatalf("gateway accepted PostgreSQL route %q: %v", insecure, err)
		}
	}
}
