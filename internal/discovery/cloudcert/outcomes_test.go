// SPDX-License-Identifier: BUSL-1.1

package cloudcert_test

import (
	"context"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/discovery/cloudcert"
)

type fakeCertProvider struct {
	name  string
	found []cloudcert.Found
	err   error
}

func (p fakeCertProvider) Name() string { return p.name }
func (p fakeCertProvider) Enumerate(context.Context) ([]cloudcert.Found, error) {
	return p.found, p.err
}

type nopCertSink struct{}

func (nopCertSink) Record(context.Context, cloudcert.Found) error { return nil }

func TestDiscoverNamesEveryProviderOutcome(t *testing.T) {
	d := cloudcert.NewDiscoverer(nopCertSink{})
	defer d.Close()
	rep := d.Discover(context.Background(), []cloudcert.Provider{
		fakeCertProvider{name: "gcp-certmanager", err: errors.New("env credential reference TRSTCTL_DISCOVERY_GCP_TOKEN is not set")},
		fakeCertProvider{name: "aws-acm", found: []cloudcert.Found{{Provider: "aws-acm", ResourceID: "arn:aws:acm:us-east-1:000000000000:certificate/demo"}}},
	})
	if rep.Providers != 2 || rep.Discovered != 1 || rep.Failed != 1 {
		t.Fatalf("report = %+v, want one discovered and one failed provider", rep)
	}
	if len(rep.Outcomes) != 2 || rep.Outcomes[0].Provider != "aws-acm" || rep.Outcomes[1].Provider != "gcp-certmanager" {
		t.Fatalf("outcomes = %+v, want one per provider sorted by name", rep.Outcomes)
	}
	if rep.Outcomes[0].Status != cloudcert.OutcomeSucceeded || rep.Outcomes[1].Status != cloudcert.OutcomeFailed || rep.Outcomes[1].Error == "" {
		t.Fatalf("outcomes = %+v, want aws succeeded and gcp failed with its reason", rep.Outcomes)
	}
}
