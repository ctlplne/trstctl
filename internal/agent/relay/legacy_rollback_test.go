// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"context"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/f5"
	"trstctl.com/trstctl/internal/connector/f5/f5test"
)

// A45: when the predecessor sits under the target-derived name from before
// fingerprint naming, the relay re-binds to it only when the intent allows the
// legacy fallback, and says so in its signed executed report.
func TestRelayRollbackReportsTheLegacyObjectReBind(t *testing.T) {
	srv := f5test.New("admin", appliancePassword)
	defer srv.Close()
	const profile = "clientssl-legacy"
	c := f5.New(srv.URL(), profile, f5.WithBasicAuthBytes("admin", []byte(appliancePassword)))
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()
	prev := []byte("-----BEGIN CERTIFICATE-----\nlegacy\n-----END CERTIFICATE-----\n")
	if _, err := connector.Run(ctx, c, ops, connector.Deployment{Target: profile, CertPEM: prev, KeyPEM: []byte(testKeyPEM)}); err != nil {
		t.Fatal(err)
	}
	current := connector.NewDeployment(profile, []byte("-----BEGIN CERTIFICATE-----\ncurrent\n-----END CERTIFICATE-----\n"), []byte(testKeyPEM))
	if _, err := connector.Run(ctx, c, ops, current); err != nil {
		t.Fatal(err)
	}
	predecessor := connector.NewDeployment(profile, prev, []byte(testKeyPEM)).Fingerprint
	config, _ := json.Marshal(map[string]any{ // #nosec G101 -- a secret:// reference name, not a credential (CWE-798)
		"endpoint": srv.URL(), "client_ssl_profile": profile, "username": "admin", "password_ref": "secret://appliance-admin",
	})
	run := func(allow bool) report {
		t.Helper()
		ch := &fakeChannel{
			jobs: []relay.Job{rollbackJob(t, 1, relay.RollbackIntent{
				Connector: "f5", Target: profile, TargetID: "t-1", PredecessorFingerprint: predecessor,
				SuccessorFingerprint: current.Fingerprint, TargetConfig: config, AllowLegacyObject: allow,
			})},
			material: map[string][]byte{"secret://appliance-admin": []byte(appliancePassword)},
		}
		if _, err := relay.RunOnce(ctx, ch, srv.Client(), 4, 60); err != nil {
			t.Fatalf("run: %v", err)
		}
		if len(ch.reports) != 1 {
			t.Fatalf("reports = %+v", ch.reports)
		}
		return ch.reports[0]
	}
	if got := run(false); got.outcome != relay.OutcomeFailed || got.detail != transport.RollbackFailedPredecessorGone {
		t.Fatalf("rollback without the legacy fallback = %+v, want predecessor gone", got)
	}
	if chain, _ := srv.Profile(profile); chain.Cert != connector.DeployedObjectName(profile, current.Fingerprint)+".crt" {
		t.Fatalf("binding changed without the fallback: %+v", chain)
	}
	if got := run(true); got.outcome != relay.OutcomeExecuted || got.detail != transport.RollbackExecutedLegacyObject {
		t.Fatalf("rollback with the legacy fallback = %+v, want executed with the legacy phrase", got)
	}
	if chain, _ := srv.Profile(profile); chain.Cert != profile+".crt" {
		t.Fatalf("profile bound to %+v, want the legacy object", chain)
	}
}
