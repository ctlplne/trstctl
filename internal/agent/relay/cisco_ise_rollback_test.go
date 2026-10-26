// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"context"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/cisco"
	"trstctl.com/trstctl/internal/connector/cisco/ciscotest"
)

// A122 (owner decision 2026-10-26): a relay rollback of a cisco target that
// names its ISE node and certificate roles moves the roles back to the
// predecessor's system certificate, redeeming only the ISE login.
func TestARelayRollsAnISETargetBackByMovingItsRoles(t *testing.T) {
	srv := ciscotest.New("ers-admin", []byte("ise-pass"))
	defer srv.Close()
	ops := connector.NewHTTPOps(srv.Client())
	direct := cisco.New(srv.URL(), "ers-admin", []byte("ise-pass"), cisco.WithISENode(srv.Node(), []string{"eap"}))
	defer direct.Close()
	var deps []connector.Deployment
	for _, label := range []string{"one", "two"} {
		dep := connector.NewDeployment("radius-vip", []byte("-----BEGIN CERTIFICATE-----\nise-relay-"+label+"\n-----END CERTIFICATE-----\n"),
			[]byte("-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----\n"))
		if _, err := connector.Run(context.Background(), direct, ops, dep); err != nil {
			t.Fatal(err)
		}
		deps = append(deps, dep)
	}
	cfg, err := json.Marshal(map[string]any{
		"endpoint": srv.URL(), "username": "ers-admin", "password_ref": "secret://connectors/ise",
		"node_hostname": srv.Node(), "certificate_roles": []string{"eap"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = relay.RollbackWithResult(context.Background(), srv.Client(), relay.RollbackIntent{
		Connector: "cisco", Target: "radius-vip", TargetConfig: cfg, CredentialRefs: []string{"secret://connectors/ise"},
		PredecessorFingerprint: deps[0].Fingerprint,
	}, relay.Material{"secret://connectors/ise": []byte("ise-pass")})
	if err != nil {
		t.Fatalf("relay rollback of an ISE target: %v", err)
	}
	if got, want := srv.RoleHolder("eap"), connector.DeployedObjectName("radius-vip", deps[0].Fingerprint); got != want {
		t.Fatalf("EAP role after the relay rollback is on %q, want %q", got, want)
	}
}
