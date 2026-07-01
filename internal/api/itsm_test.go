package api

import (
	"context"
	"testing"
)

func TestServiceNowBindingApprovalRequiresConfiguredURLTokenAndPrivateFlag(t *testing.T) {
	a := New(nil, nil, nil, WithServiceNowBindings(ServiceNowBinding{
		InstanceURL:          "https://example.service-now.com/",
		TokenRef:             "env:TRSTCTL_SERVICENOW_TOKEN",
		AllowPrivateEndpoint: false,
	}))

	if _, err := a.approvedServiceNowBinding(serviceNowTicketRequest{
		InstanceURL:      "https://example.service-now.com",
		TokenRef:         "env:TRSTCTL_SERVICENOW_TOKEN",
		ShortDescription: "ok",
	}); err != nil {
		t.Fatalf("approved binding rejected: %v", err)
	}

	for _, tc := range []serviceNowTicketRequest{
		{InstanceURL: "https://attacker.example.test", TokenRef: "env:TRSTCTL_SERVICENOW_TOKEN"},
		{InstanceURL: "https://example.service-now.com", TokenRef: "env:AWS_SECRET_ACCESS_KEY"},
		{InstanceURL: "https://example.service-now.com", TokenRef: "env:TRSTCTL_SERVICENOW_TOKEN", AllowPrivateEndpoint: true},
	} {
		if _, err := a.approvedServiceNowBinding(tc); err == nil {
			t.Fatalf("unapproved binding accepted: %+v", tc)
		}
	}
}

func TestOutboundEnvCredentialRefsRequireOperatorApproval(t *testing.T) {
	a := New(nil, nil, nil, WithOutboundEnvCredentialRefs("env:TRSTCTL_SPLUNK_TOKEN", "env:TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY"))

	_, err := a.responseIntegrationDispatchCommand(context.Background(), "tenant-sec-001", responseIntegrationDispatchRequest{
		Title: "incident",
		Destinations: []responseIntegrationDestinationRequest{{
			Provider:    "splunk",
			EndpointURL: "https://splunk.example.test/services/collector",
			TokenRef:    "env:AWS_SECRET_ACCESS_KEY",
		}},
	})
	if err == nil {
		t.Fatal("arbitrary env credential ref was accepted for response integration dispatch")
	}

	if err := a.requireDiscoveryCredentialRefsAllowed([]byte(`{
		"providers":[{
			"provider":"aws-acm",
			"region":"us-east-1",
			"endpoint":"https://acm.us-east-1.amazonaws.com",
			"secret_access_key_ref":"env:AWS_SECRET_ACCESS_KEY"
		}]
	}`)); err == nil {
		t.Fatal("arbitrary env credential ref was accepted for discovery source config")
	}

	if err := a.requireDiscoveryCredentialRefsAllowed([]byte(`{
		"providers":[{
			"provider":"aws-acm",
			"region":"us-east-1",
			"endpoint":"https://acm.us-east-1.amazonaws.com",
			"secret_access_key_ref":"env:TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY"
		}]
	}`)); err != nil {
		t.Fatalf("operator-approved discovery env credential ref rejected: %v", err)
	}
}
