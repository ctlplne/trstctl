// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/outboundcred"
)

func TestServiceNowBindingApprovalRequiresConfiguredURLTokenAndPrivateFlag(t *testing.T) {
	a := New(nil, nil, nil, WithServiceNowBindings(ServiceNowBinding{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		InstanceURL:          "https://example.service-now.com/",
		TokenRef:             "env:TRSTCTL_SERVICENOW_TOKEN",
		AllowPrivateEndpoint: false,
	}))

	if _, err := a.approvedServiceNowBinding(serviceNowTicketRequest{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		InstanceURL:      "https://example.service-now.com",
		TokenRef:         "env:TRSTCTL_SERVICENOW_TOKEN",
		ShortDescription: "ok",
	}, false); err != nil {
		t.Fatalf("approved binding rejected: %v", err)
	}

	for _, tc := range []serviceNowTicketRequest{
		{InstanceURL: "https://attacker.example.test", TokenRef: "env:TRSTCTL_SERVICENOW_TOKEN"},                               // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		{InstanceURL: "https://example.service-now.com", TokenRef: "env:AWS_SECRET_ACCESS_KEY"},                                // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		{InstanceURL: "https://example.service-now.com", TokenRef: "env:TRSTCTL_SERVICENOW_TOKEN", AllowPrivateEndpoint: true}, // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
	} {
		if _, err := a.approvedServiceNowBinding(tc, false); err == nil {
			t.Fatalf("unapproved binding accepted: %+v", tc)
		}
	}
}

func TestServiceNowRelayBindingCannotAuthorizeControlPlaneTicket(t *testing.T) {
	ref := "secret://itsm/cmdb-qa-token"
	a := New(nil, nil, nil, WithServiceNowBindings(ServiceNowBinding{
		InstanceURL: "https://cmdb.qa.invalid",
		TokenRef:    ref,
		RelayOnly:   true,
	}))
	req := serviceNowTicketRequest{InstanceURL: "https://cmdb.qa.invalid", TokenRef: ref}
	if _, err := a.approvedServiceNowBinding(req, false); err == nil {
		t.Fatal("relay-only CMDB binding authorized control-plane ticket dispatch")
	}
	if _, err := a.approvedServiceNowBinding(req, true); err != nil {
		t.Fatalf("relay-only CMDB binding rejected by CMDB setup: %v", err)
	}
}

// CR-008: an approved env credential reference is usable only by the tenant, the
// integration kind and toward the origins the operator bound it to. The pre-fix
// form of this test accepted any approved reference for any tenant and endpoint;
// that expectation was the defect.
func TestOutboundEnvCredentialRefsRequireOperatorApproval(t *testing.T) {
	const (
		tenant      = "c8000000-0000-4000-8000-000000000001"
		otherTenant = "c8000000-0000-4000-8000-000000000002"
	)
	bindings, err := outboundcred.New([]outboundcred.Binding{ // #nosec G101 -- reference names only; no credential value (CWE-798)
		{Ref: "env:TRSTCTL_SPLUNK_TOKEN", TenantID: tenant, Integrations: []string{outboundcred.IntegrationResponseIntegration},
			Origins: []string{"https://splunk.example.test"}},
		{Ref: "env:TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY", TenantID: tenant, Integrations: []string{"cloud_certificate"},
			Origins: []string{"https://acm.us-east-1.amazonaws.com"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	a := New(nil, nil, nil, WithOutboundEnvCredentialBindings(bindings))
	dispatch := func(tenantID, ref, endpoint string) error {
		_, err := a.responseIntegrationDispatchCommand(context.Background(), tenantID, responseIntegrationDispatchRequest{
			Title: "incident",
			Destinations: []responseIntegrationDestinationRequest{{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
				Provider:    "splunk",
				EndpointURL: endpoint,
				TokenRef:    ref,
			}},
		})
		return err
	}
	if err := dispatch(tenant, "env:AWS_SECRET_ACCESS_KEY", "https://splunk.example.test/services/collector"); err == nil {
		t.Fatal("arbitrary env credential ref was accepted for response integration dispatch")
	}
	if err := dispatch(tenant, "env:TRSTCTL_SPLUNK_TOKEN", "https://splunk.example.test/services/collector"); err != nil {
		t.Fatalf("the bound response-integration ref was rejected: %v", err)
	}
	if err := dispatch(otherTenant, "env:TRSTCTL_SPLUNK_TOKEN", "https://splunk.example.test/services/collector"); err == nil {
		t.Fatal("another tenant's response integration accepted a ref bound to a different tenant")
	}
	if err := dispatch(tenant, "env:TRSTCTL_SPLUNK_TOKEN", "https://collector.example.test/services/collector"); err == nil {
		t.Fatal("a bound ref was accepted toward an origin its binding does not name")
	}

	discovery := func(tenantID, kind, ref, endpoint string) error {
		return a.requireDiscoveryCredentialRefsBound(tenantID, kind, []byte(`{
			"providers":[{
				"provider":"aws-acm",
				"region":"us-east-1",
				"endpoint":"`+endpoint+`",
				"secret_access_key_ref":"`+ref+`"
			}]
		}`))
	}
	if err := discovery(tenant, "cloud_certificate", "env:AWS_SECRET_ACCESS_KEY", "https://acm.us-east-1.amazonaws.com"); err == nil {
		t.Fatal("arbitrary env credential ref was accepted for discovery source config")
	}
	if err := discovery(tenant, "cloud_certificate", "env:TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY", "https://acm.us-east-1.amazonaws.com"); err != nil {
		t.Fatalf("operator-approved discovery env credential ref rejected: %v", err)
	}
	if err := discovery(otherTenant, "cloud_certificate", "env:TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY", "https://acm.us-east-1.amazonaws.com"); err == nil {
		t.Fatal("another tenant's discovery source accepted a ref bound to a different tenant")
	}
	if err := discovery(tenant, "cloud_secret", "env:TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY", "https://acm.us-east-1.amazonaws.com"); err == nil {
		t.Fatal("a discovery kind the binding does not name accepted the ref")
	}
	if err := discovery(tenant, "cloud_certificate", "env:TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY", "https://acm.collector.example.test"); err == nil {
		t.Fatal("a discovery endpoint the binding does not name accepted the ref")
	}
}
