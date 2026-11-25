// SPDX-License-Identifier: BUSL-1.1

package dbdsn

import (
	"errors"
	"testing"
)

func TestCR039MySQLGatewayRouteCannotAuthorizePlaintextSignIn(t *testing.T) {
	target, err := Parse(MySQL, []byte("fixture:fixture@tcp(db.example.test:3306)/orders"), Gateway)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Wipe()
	mode, err := GatewayTLSMode(MySQL, target, false)
	if err != nil || mode != GatewayVerifiedTLS {
		t.Fatalf("gateway authorized insecure MySQL mode=%q err=%v", mode, err)
	}
	route := GatewayRoute{Revision: GatewayRouteRevision, ProviderID: "mysql-provider",
		Hosts: []string{"db.example.test:3306"}, Database: "orders", TLS: GatewayPlain, Source: OperatorFileSource}
	if err := route.Validate(MySQL, false); !errors.Is(err, ErrGatewayRoute) {
		t.Fatalf("gateway accepted an explicit plaintext MySQL route: %v", err)
	}
}

func TestCR039MySQLGatewayRejectsNativeSkipVerifySetting(t *testing.T) {
	admin, err := Parse(MySQL, []byte("fixture:fixture@tcp(db.example.test:3306)/orders?tls=skip-verify"), Admin)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Wipe()
	if mode, err := GatewayTLSMode(MySQL, admin, false); !errors.Is(err, ErrTrust) {
		t.Fatalf("gateway advertised mode %q from native skip-verify setting: %v", mode, err)
	}
}
