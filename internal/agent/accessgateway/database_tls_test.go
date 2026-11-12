// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestDatabaseSessionCarriesItsProvidersCAA256L1 is A256-L1: a PostgreSQL,
// Redis or MongoDB session's job carries its provider's CA and certificate
// name in fields of their own, which the gateway's sign-in verifies against.
// No other session type carries them, and a database session still names no
// HTTP upstream.
func TestDatabaseSessionCarriesItsProvidersCAA256L1(t *testing.T) {
	base := SessionIntent{SessionID: "s", TargetID: "db", ExpiresAt: time.Now(),
		TicketDigest: TicketDigest("t"), CredentialRef: CredentialRef("s"), RequiredAgentID: "gw",
		DatabaseCAPEM: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n", DatabaseServerName: "db.private.test"}
	for _, target := range []string{TargetPostgres, TargetRedis, TargetMongo} {
		in := base
		in.TargetType = target
		if err := ValidateSessionIntent(in); err != nil {
			t.Fatalf("%s session with its provider's CA: %v", target, err)
		}
		trust := in.upstreamTrust()
		if string(trust.caPEM) != in.DatabaseCAPEM || trust.serverName != "db.private.test" {
			t.Fatalf("%s trust = %+v", target, trust)
		}
		raw, err := json.Marshal(in)
		if err != nil || !strings.Contains(string(raw), `"database_ca_pem"`) || !strings.Contains(string(raw), `"database_server_name":"db.private.test"`) {
			t.Fatalf("%s job payload = %s (%v)", target, raw, err)
		}
	}
	for _, target := range []string{TargetMySQL, TargetClickHouse, TargetKubernetes} {
		in := base
		in.TargetType = target
		if target == TargetClickHouse || target == TargetKubernetes {
			in.UpstreamURL = "https://db.private.test:8443"
		}
		if err := ValidateSessionIntent(in); err == nil || !strings.Contains(err.Error(), "database CA") {
			t.Fatalf("%s session carrying a database CA = %v", target, err)
		}
	}
	upstream := base
	upstream.TargetType, upstream.DatabaseCAPEM, upstream.DatabaseServerName, upstream.UpstreamCAPEM = TargetPostgres, "", "", "pem"
	if ValidateSessionIntent(upstream) == nil {
		t.Fatal("a PostgreSQL session naming an HTTP upstream's CA was accepted")
	}
	none := base
	none.TargetType, none.DatabaseCAPEM, none.DatabaseServerName = TargetPostgres, "", ""
	if trust := none.upstreamTrust(); trust.caPEM != nil || trust.serverName != "" {
		t.Fatalf("a session with no CA = %+v", trust)
	}
}
