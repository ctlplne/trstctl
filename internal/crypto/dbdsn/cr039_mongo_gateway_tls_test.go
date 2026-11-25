// SPDX-License-Identifier: BUSL-1.1

package dbdsn

import (
	"errors"
	"testing"
)

func TestCR039MongoGatewayRouteCannotAuthorizePlaintext(t *testing.T) {
	target, err := Parse(Mongo, []byte("mongodb://fixture:fixture@db.private.test:27017/orders?authSource=orders"), Gateway)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Wipe()
	mode, err := GatewayTLSMode(Mongo, target, false)
	if err != nil || mode != GatewayVerifiedTLS {
		t.Fatalf("gateway authorized plaintext MongoDB: mode=%q err=%v", mode, err)
	}
	route := GatewayRoute{Revision: GatewayRouteRevision, ProviderID: "mongo-provider", Hosts: target.Hosts,
		Database: "orders", TLS: GatewayPlain, Source: OperatorFileSource}
	if err := route.Validate(Mongo, false); !errors.Is(err, ErrGatewayRoute) {
		t.Fatalf("gateway accepted a plaintext MongoDB route: %v", err)
	}
}
