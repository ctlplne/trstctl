// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/f5"
	"trstctl.com/trstctl/internal/connector/f5/f5test"
)

func takedownJob(t *testing.T, jobID int64, intent relay.TakedownIntent) relay.Job {
	t.Helper()
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	return relay.Job{JobID: jobID, Kind: relay.KindConnectorTakedown, Attempt: 1, Payload: payload}
}

// A43: a family that cannot remove objects is refused before any credential
// is redeemed, and the shipped census advertises the kind for network relays.
func TestRelayRefusesTakedownForAnUnsupportedFamilyBeforeRedeeming(t *testing.T) {
	if !slices.Contains(relay.ClaimableKinds(), relay.KindConnectorTakedown) {
		t.Fatal("the relay never asks for connector.takedown")
	}
	advertised := false
	for _, shipped := range relay.ShippedJobKinds() {
		if shipped.Kind == relay.KindConnectorTakedown {
			advertised = slices.Contains(shipped.Roles, "network") && slices.Contains(shipped.Connectors, "f5") &&
				!slices.Contains(shipped.Connectors, "cisco")
		}
	}
	if !advertised {
		t.Fatal("connector.takedown must be advertised for network relays with the takedown-capable families only")
	}
	ch := &fakeChannel{
		jobs: []relay.Job{takedownJob(t, 1, relay.TakedownIntent{
			Connector: "cisco", Target: "edge", TargetID: "t-1", TargetRevision: "r-1", Fingerprint: strings.Repeat("a", 64),
		})},
		material: map[string][]byte{"secret://appliance-admin": []byte(appliancePassword)},
	}
	if _, err := relay.RunOnce(context.Background(), ch, http.DefaultClient, 4, 60); err != nil {
		t.Fatalf("run: %v", err)
	}
	if ch.redeemed != 0 {
		t.Fatalf("relay redeemed %d credentials for a takedown it cannot perform", ch.redeemed)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed || ch.reports[0].detail != transport.TakedownRefusedUnsupported {
		t.Fatalf("reports = %+v, want one refusal", ch.reports)
	}
}

// The relay removes an unbound object on a BIG-IP double and reports the
// bound one as bound, both as signed executed reports whose digest the
// receiver can re-derive.
func TestRelayTakedownRemovesUnboundObjectsAndReportsBoundOnes(t *testing.T) {
	srv := f5test.New("admin", appliancePassword)
	defer srv.Close()
	const profile = "clientssl-app"
	c := f5.New(srv.URL(), profile, f5.WithBasicAuthBytes("admin", []byte(appliancePassword)))
	ops := connector.NewHTTPOps(srv.Client())
	ctx := context.Background()
	first := connector.NewDeployment(profile, []byte("-----BEGIN CERTIFICATE-----\nfirst\n-----END CERTIFICATE-----\n"), []byte(testKeyPEM))
	if _, err := connector.Run(ctx, c, ops, first); err != nil {
		t.Fatal(err)
	}
	second := connector.NewDeployment(profile, []byte("-----BEGIN CERTIFICATE-----\nsecond\n-----END CERTIFICATE-----\n"), []byte(testKeyPEM))
	if _, err := connector.Run(ctx, c, ops, second); err != nil {
		t.Fatal(err)
	}
	config, _ := json.Marshal(map[string]any{ // #nosec G101 -- a secret:// reference name, not a credential (CWE-798)
		"endpoint": srv.URL(), "client_ssl_profile": profile, "username": "admin", "password_ref": "secret://appliance-admin",
	})
	intent := func(id int64, fingerprint string) relay.Job {
		return takedownJob(t, id, relay.TakedownIntent{
			Connector: "f5", Target: profile, TargetID: "t-1", TargetRevision: "r-1",
			Fingerprint: fingerprint, TargetConfig: config,
		})
	}
	ch := &fakeChannel{
		jobs:     []relay.Job{intent(1, first.Fingerprint), intent(2, second.Fingerprint)},
		material: map[string][]byte{"secret://appliance-admin": []byte(appliancePassword)},
	}
	executed, err := relay.RunOnce(ctx, ch, srv.Client(), 4, 60)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if executed != 1 || ch.redeemed != 2 || len(ch.reports) != 2 {
		t.Fatalf("executed=%d redeemed=%d reports=%+v", executed, ch.redeemed, ch.reports)
	}
	var states []string
	for i, rep := range ch.reports {
		if rep.outcome != relay.OutcomeExecuted {
			t.Fatalf("report %d = %+v, want executed", i, rep)
		}
		var report relay.TakedownReport
		if err := json.Unmarshal([]byte(rep.detail), &report); err != nil {
			t.Fatal(err)
		}
		var queued relay.TakedownIntent
		_ = json.Unmarshal(ch.jobs[i].Payload, &queued)
		if err := relay.ValidateTakedownReport(queued, report, rep.evidence); err != nil {
			t.Fatalf("report %d rejected by the receiver: %v", i, err)
		}
		states = append(states, report.State)
	}
	if !slices.Equal(states, []string{relay.TakedownRemoved, relay.TakedownBound}) {
		t.Fatalf("states = %v", states)
	}
	firstBase := connector.DeployedObjectName(profile, first.Fingerprint)
	if srv.InstalledCert(firstBase + ".crt") {
		t.Fatal("the unbound predecessor object survived")
	}
	if chain, _ := srv.Profile(profile); chain.Cert != connector.DeployedObjectName(profile, second.Fingerprint)+".crt" {
		t.Fatalf("profile binding changed: %+v", chain)
	}
}
