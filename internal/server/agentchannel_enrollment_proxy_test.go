// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
)

func TestServingEnrollmentProxyReportRequiresExactTopologyAndMeasuredUpstream(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		report transport.EnrollmentProxyReport
	}{
		{name: "no segment", report: transport.EnrollmentProxyReport{Serving: true, PublicURL: "https://relay.example", UnknownUpstreams: 1}},
		{name: "no public URL", report: transport.EnrollmentProxyReport{Serving: true, Segment: "plant-7", UnknownUpstreams: 1}},
		{name: "non HTTPS URL", report: transport.EnrollmentProxyReport{Serving: true, Segment: "plant-7", PublicURL: "http://relay.example", UnknownUpstreams: 1}},
		{name: "URL path", report: transport.EnrollmentProxyReport{Serving: true, Segment: "plant-7", PublicURL: "https://relay.example/acme", UnknownUpstreams: 1}},
		{name: "no upstream", report: transport.EnrollmentProxyReport{Serving: true, Segment: "plant-7", PublicURL: "https://relay.example"}},
		{name: "negative counter", report: transport.EnrollmentProxyReport{Serving: true, Segment: "plant-7", PublicURL: "https://relay.example", UnknownUpstreams: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := validatedEnrollmentProxyReport(&tc.report); err == nil {
				t.Fatalf("accepted invalid serving report: %+v", tc.report)
			}
		})
	}

	got, err := validatedEnrollmentProxyReport(&transport.EnrollmentProxyReport{
		Serving: true, Segment: " plant-7 ", PublicURL: "https://relay.example/", UnknownUpstreams: 1,
	})
	if err != nil {
		t.Fatalf("valid unverified topology: %v", err)
	}
	if got.Segment != "plant-7" || got.PublicURL != "https://relay.example" || got.UnknownUpstreams != 1 {
		t.Fatalf("validated topology = %+v, want canonical segment, authority, and unknown count", got)
	}
}
