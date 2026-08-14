// SPDX-License-Identifier: MPL-2.0

package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"trstctl.com/trstctl/internal/discovery/adcs"
)

type adcsDoerFunc func(*http.Request) (*http.Response, error)

func (f adcsDoerFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

type adcsCloseErrorBody struct{ io.Reader }

func (adcsCloseErrorBody) Close() error { return errors.New("fixture close failed") }

func TestADCSEnrollmentEvidenceFailsClosedWhenResponseCannotClose(t *testing.T) {
	target := adcs.EnrollmentEndpointTarget{
		Kind: adcs.EndpointWebEnrollment, URL: "https://ca.corp.example/certsrv/",
	}
	got := observeEnrollmentEndpoint(t.Context(), adcsDoerFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Header:     http.Header{"WWW-Authenticate": []string{"Negotiate"}},
			Body:       adcsCloseErrorBody{Reader: strings.NewReader("ignored")},
		}, nil
	}), target)
	if got.Kind != target.Kind || got.URL != target.URL || got.State != adcs.EndpointUnreachable ||
		got.HTTPStatus != 0 || got.TLSVerified || len(got.Authentication) != 0 {
		t.Fatalf("close-failed endpoint = %+v; want target identity plus unreachable-only evidence", got)
	}
}

func TestADCSSearchUsesDACLOnlySecurityDescriptorControlAUD35(t *testing.T) {
	controls := ldapSearchControls(adcs.SearchRequest{DACLOnly: true})
	if len(controls) != 1 {
		t.Fatalf("controls = %d, want one DACL-only control", len(controls))
	}
	control, ok := controls[0].(*ldap.ControlString)
	if !ok {
		t.Fatalf("control type = %T, want *ldap.ControlString", controls[0])
	}
	if control.ControlType != ldapServerSDFlagsOID || !control.Criticality {
		t.Fatalf("control = %+v, want critical %s", control, ldapServerSDFlagsOID)
	}
	want := []byte{0x30, 0x03, 0x02, 0x01, 0x04}
	if !bytes.Equal([]byte(control.ControlValue), want) {
		t.Fatalf("SDFlags control value = %x, want DACL_SECURITY_INFORMATION BER %x", []byte(control.ControlValue), want)
	}
	if got := ldapSearchControls(adcs.SearchRequest{}); len(got) != 0 {
		t.Fatalf("ordinary LDAP search got %d controls, want none", len(got))
	}
}

func TestADCSEnrollmentEvidenceIsLiveBoundedAndClosedAUD37(t *testing.T) {
	inv := adcs.Inventory{EnrollmentServices: []adcs.EnrollmentService{{
		Name: "CORP-CA", DNSName: "ca.corp.example",
	}}}
	intent := adcs.InventoryIntent{EnrollmentEndpoints: []adcs.EnrollmentEndpointTarget{
		{EnrollmentService: "CORP-CA", Kind: adcs.EndpointWebEnrollment, URL: "https://ca.corp.example/certsrv/"},
		{EnrollmentService: "CORP-CA", Kind: adcs.EndpointNDESAdmin, URL: "http://ca.corp.example/certsrv/mscep_admin/"},
	}}
	doer := adcsDoerFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Range") != "bytes=0-0" {
			t.Fatal("live endpoint probe did not bound a cooperative response")
		}
		status := http.StatusUnauthorized
		headers := http.Header{}
		headers.Add("WWW-Authenticate", "Negotiate")
		headers.Add("WWW-Authenticate", "NTLM TlRMTVNTUAAB")
		if strings.Contains(req.URL.Path, "mscep_admin") {
			status, headers = http.StatusOK, http.Header{}
		}
		return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader("body is never evidence"))}, nil
	})
	if err := enrichADCSInventory(context.Background(), intent, &inv, doer, func(context.Context, adcs.EnrollmentService) adcs.EnrollmentAgentRestrictions {
		return adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceDisabled, Source: "live_test_fixture"}
	}); err != nil {
		t.Fatalf("enrich inventory: %v", err)
	}
	service := inv.EnrollmentServices[0]
	if service.AgentRestrictions.State != adcs.EvidenceDisabled || len(service.Endpoints) != 2 {
		t.Fatalf("live service evidence = %+v", service)
	}
	web := service.Endpoints[1]
	if web.Kind != adcs.EndpointWebEnrollment || web.State != adcs.EndpointAuthenticationNeeded ||
		!web.TLSVerified || strings.Join(web.Authentication, ",") != "NTLM,Negotiate" ||
		web.ExtendedProtection != adcs.EvidenceUnobserved {
		t.Fatalf("web enrollment evidence = %+v", web)
	}
	admin := service.Endpoints[0]
	if admin.Kind != adcs.EndpointNDESAdmin || admin.State != adcs.EndpointAnonymousAccess || admin.TLSVerified {
		t.Fatalf("NDES admin evidence = %+v", admin)
	}
}

func TestADCSEndpointClientKeepsExplicitSSRFEgressBoundaryAUD37(t *testing.T) {
	intent := adcs.InventoryIntent{
		AllowPrivateEndpoint: true,
		PrivateEgressCIDRs:   []string{"10.42.8.0/24"},
		EnrollmentEndpoints: []adcs.EnrollmentEndpointTarget{{
			EnrollmentService: "CORP-CA", Kind: adcs.EndpointNDES, URL: "https://ca.corp.example/certsrv/mscep/",
		}},
	}
	client, err := newADCSEndpointClient(intent)
	if err != nil {
		t.Fatalf("build endpoint client: %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.DialContext == nil || transport.TLSClientConfig == nil {
		t.Fatalf("client did not preserve safe dial and crypto TLS boundaries: %#v", client.Transport)
	}
	request, err := http.NewRequest(http.MethodGet, "https://other.corp.example/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckRedirect(request, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect policy = %v, want refusal", err)
	}

	intent.PrivateEgressCIDRs = []string{"169.254.0.0/16"}
	if _, err := newADCSEndpointClient(intent); err == nil {
		t.Fatal("metadata/link-local egress boundary was accepted")
	}
}

func TestCAAgentRestrictionParserFailsUnknownHonestAUD37(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		succeeded bool
		want      adcs.EvidenceState
	}{
		{"configured", "EnrollmentAgentRights REG_BINARY 01", true, adcs.EvidenceEnabled},
		{"missing", "CertUtil: -getreg command FAILED: 0x80070002", false, adcs.EvidenceDisabled},
		{"denied", "CertUtil: Access is denied", false, adcs.EvidenceUnobserved},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := parseCAAgentRestrictions([]byte(test.output), test.succeeded); got.State != test.want {
				t.Fatalf("state = %q, want %q (%+v)", got.State, test.want, got)
			}
		})
	}
}
