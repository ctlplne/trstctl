// SPDX-License-Identifier: BUSL-1.1

package pgsignin

import (
	"context"
	"net"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/certtest"
)

func TestGatewayPostgresRefusesFileOptionsInSessionCredential(t *testing.T) {
	for _, tc := range []struct{ name, dsn string }{
		{"keyword root", "host=db.test user=review password=plain sslrootcert=unused"},
		{"URI root", "postgres://review:plain@db.test/orders?sslrootcert=unused"},
		{"client key", "host=db.test user=review password=plain sslkey=unused"},
		{"service metadata", "host=db.test user=review password=plain servicefile=unused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target, err := ParseDSN([]byte(tc.dsn))
			defer target.Wipe()
			if err == nil {
				t.Fatal("the session credential supplied a file option")
			}
		})
	}
}

func TestGatewayPostgresExplicitTrustRequiresTLS(t *testing.T) {
	ca, _, _, err := certtest.PrivateCAServer("db.test")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	host, port, err := net.SplitHostPort(fakePostgres(t, 0, 'N', nil))
	if err != nil {
		t.Fatal(err)
	}
	session, err := SignIn(ctx, []byte("host="+host+" port="+port+" user=review password=plain dbname=orders sslmode=prefer"),
		Options{RootCAPEM: ca, ServerName: "db.test"})
	if session != nil {
		_ = session.Conn.Close()
	}
	if err == nil {
		t.Fatal("the explicit trust decision allowed a plaintext sign-in")
	}
}
