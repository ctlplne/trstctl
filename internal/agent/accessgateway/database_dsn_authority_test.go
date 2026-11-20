// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto/dbdsn"
	"trstctl.com/trstctl/internal/netsec"
)

type databaseClaimObserver struct {
	*fakeChannel
	redemptions int
}

func (c *databaseClaimObserver) RedeemJobCredential(context.Context, int64, int) (map[string][]byte, error) {
	c.redemptions++
	return nil, errors.New("fixture does not hold credentials")
}

func TestDatabaseGatewayRejectsABindinglessJobBeforeRedemption(t *testing.T) {
	channel := &databaseClaimObserver{fakeChannel: &fakeChannel{}}
	gateway := &Gateway{cfg: Config{Channel: channel, Now: time.Now}}
	const id = "11111111-1111-4111-8111-111111111111"
	payload, err := json.Marshal(SessionIntent{SessionID: id, TargetType: TargetPostgres, TargetID: "database",
		ExpiresAt: time.Now().Add(time.Minute), TicketDigest: TicketDigest("ticket"), RequiredAgentID: "gateway",
		CredentialRef: CredentialRef(id)})
	if err != nil {
		t.Fatal(err)
	}
	job := relay.Job{JobID: 7, Kind: KindSession, Attempt: 1, Payload: payload}
	gateway.start(t.Context(), job)
	if channel.redemptions != 0 {
		t.Fatal("the gateway requested credentials for a job without a guarded route")
	}
}

func TestGatewayDatabaseDialEnforcesSourcePolicyAtResolution(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	address := net.JoinHostPort("localhost", port)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	intent := SessionIntent{TargetType: TargetPostgres,
		DatabaseRoute: &dbdsn.GatewayRoute{Revision: dbdsn.GatewayRouteRevision, ProviderID: "postgres-provider",
			Hosts: []string{address}, Database: "orders", TLS: dbdsn.GatewayPlain, Source: dbdsn.TenantStoredSource}}
	gateway := &Gateway{}
	dial, err := gateway.bindDatabaseDial(intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dial(ctx, "tcp", address); !errors.Is(err, netsec.ErrSSRFBlocked) {
		t.Fatalf("the ordinary hostname admitted an unapproved resolved IP: %v", err)
	}
	intent.DatabaseRoute.PrivateCIDRs = []string{"127.0.0.1/32"}
	dial, err = gateway.bindDatabaseDial(intent)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dial(ctx, "tcp", address)
	if err != nil {
		t.Fatalf("declared local fixture CIDR: %v", err)
	}
	_ = conn.Close()
	if _, err := dial(ctx, "tcp", ln.Addr().String()); !errors.Is(err, dbdsn.ErrGatewayRoute) {
		t.Fatal("the gateway accepted a host spelling outside the bound job")
	}
}

func TestGatewayDatabaseTrustRejectsMalformedAndUnboundedInputs(t *testing.T) {
	for _, kind := range []string{TargetPostgres, TargetMongo, TargetRedis} {
		t.Run(kind, func(t *testing.T) {
			for _, tc := range []struct{ name, pem, serverName string }{
				{"invalid PEM", "not a certificate", "db.test"},
				{"oversized PEM", strings.Repeat("x", 256*1024+1), "db.test"},
				{"non-host name", "", "db.test/path"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					intent := SessionIntent{SessionID: "s", TargetID: "db", TargetType: kind,
						ExpiresAt: time.Now().Add(time.Minute), TicketDigest: TicketDigest("t"),
						RequiredAgentID: "gateway", CredentialRef: CredentialRef("s"),
						DatabaseCAPEM: tc.pem, DatabaseServerName: tc.serverName}
					if err := ValidateSessionIntent(intent); err == nil {
						t.Fatal("invalid database trust passed gateway job admission")
					}
				})
			}
		})
	}
}
