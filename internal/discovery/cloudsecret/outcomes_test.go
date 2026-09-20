// SPDX-License-Identifier: BUSL-1.1

package cloudsecret_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/discovery/cloudsecret"
)

type fakeSecretProvider struct {
	name  string
	found []cloudsecret.Found
	err   error
}

func (p fakeSecretProvider) Name() string { return p.name }
func (p fakeSecretProvider) Enumerate(context.Context) ([]cloudsecret.Found, error) {
	return p.found, p.err
}

type nopSecretSink struct{}

func (nopSecretSink) Record(context.Context, cloudsecret.Found) error { return nil }

// A pass names every provider's outcome so a partial run can say which
// provider failed and why instead of only counting failures.
func TestDiscoverNamesEveryProviderOutcome(t *testing.T) {
	d := cloudsecret.NewDiscoverer(nopSecretSink{})
	defer d.Close()
	rep := d.Discover(context.Background(), []cloudsecret.Provider{
		fakeSecretProvider{name: "gcp-secret-manager", err: errors.New("env credential reference TRSTCTL_DISCOVERY_GCP_SM_TOKEN is not set")},
		fakeSecretProvider{name: "aws-secrets-manager", found: []cloudsecret.Found{{Kind: "certificate", Provider: "aws-secrets-manager", SecretName: "demo/edge-gateway/tls"}}}, // #nosec G101 -- fabricated fixture secret name; the test needs the shape, no value is real (CWE-798)
	})
	if rep.Providers != 2 || rep.Discovered != 1 || rep.Failed != 1 {
		t.Fatalf("report = %+v, want one discovered and one failed provider", rep)
	}
	if len(rep.Outcomes) != 2 || rep.Outcomes[0].Provider != "aws-secrets-manager" || rep.Outcomes[1].Provider != "gcp-secret-manager" {
		t.Fatalf("outcomes = %+v, want one per provider sorted by name", rep.Outcomes)
	}
	if rep.Outcomes[0].Status != cloudsecret.OutcomeSucceeded || rep.Outcomes[0].Error != "" {
		t.Fatalf("aws outcome = %+v, want succeeded without error", rep.Outcomes[0])
	}
	if rep.Outcomes[1].Status != cloudsecret.OutcomeFailed || rep.Outcomes[1].Error == "" {
		t.Fatalf("gcp outcome = %+v, want failed with the provider's reason", rep.Outcomes[1])
	}
}
