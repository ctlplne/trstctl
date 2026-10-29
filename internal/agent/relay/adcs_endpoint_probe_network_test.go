// SPDX-License-Identifier: BUSL-1.1
package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/discovery/adcs"
	"trstctl.com/trstctl/internal/netsec"
)

// Run in the owned private container network, never by relaxing the production
// loopback/metadata guard. The directory is real Samba; HTTP/TLS is a stand-in.
func TestADCSLDAPEndpointProbeRealNetworkStandin(t *testing.T) {
	configPath := os.Getenv("TRSTCTL_ADCS_PROBE_NETWORK_CONFIG")
	if configPath == "" {
		t.Skip("set TRSTCTL_ADCS_PROBE_NETWORK_CONFIG for the owned private-network Samba/HTTP fixture")
	}
	raw, err := os.ReadFile(configPath) // #nosec G304,G703 -- operator-selected public configuration for the owned network fixture (CWE-22).
	if err != nil {
		t.Fatal(err)
	}
	intent, err := adcs.ResolveInventoryIntent(raw)
	if err != nil {
		t.Fatal(err)
	}
	intent.ID, intent.SourceID = "a229-network-run", "a229-network-source"
	allowed, err := netsec.ParseRelayEgress(intent.PrivateEgressCIDRs)
	if err != nil {
		t.Fatal(err)
	}
	SetEgressPolicy(allowed)
	t.Cleanup(func() { SetEgressPolicy(nil) })
	readAudit := func() []map[string]any {
		t.Helper()
		audit, err := os.ReadFile(os.Getenv("TRSTCTL_ADCS_PROBE_HTTP_AUDIT")) // #nosec G304,G703 -- exact owned public request-audit fixture; no header values (CWE-22).
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		var out []map[string]any
		for _, line := range bytes.Split(audit, []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			var entry map[string]any
			if err := json.Unmarshal(line, &entry); err != nil {
				t.Fatal(err)
			}
			out = append(out, entry)
		}
		return out
	}
	collect := func(command adcs.InventoryIntent) ADCSReport {
		t.Helper()
		password, err := os.ReadFile(os.Getenv("TRSTCTL_ADCS_PROBE_PASSWORD_FILE")) // #nosec G304,G703 -- exact owned credential fixture; bytes wiped, never printed or retained (CWE-22).
		if err != nil {
			t.Fatal(err)
		}
		defer secret.Wipe(password)
		result, err := InventoryADCS(t.Context(), command, Material{command.PasswordRef: password})
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range password {
			if value != 0 {
				t.Fatal("LDAP borrowed credential survived authentication")
			}
		}
		return result
	}
	before := len(readAudit())
	result := collect(intent)
	if result.Status != "succeeded" || result.DirectoryVerified || result.Inventory.EndpointProbePage == nil || result.Inventory.EndpointProbePage.TotalTargets != 4 {
		t.Fatalf("real collection status=%s directory_verified=%t page=%+v", result.Status, result.DirectoryVerified, result.Inventory.EndpointProbePage)
	}
	if intent.NestedGroupsEnabled {
		expectedSID := os.Getenv("TRSTCTL_ADCS_PROBE_EXPECTED_MEMBER_SID")
		if expectedSID == "" {
			t.Fatal("combined proof requires an explicit owned member SID")
		}
		found := false
		for _, template := range result.Inventory.Templates {
			if template.EnrollmentMembership == nil || template.EnrollmentMembership.State != "complete" {
				continue
			}
			for _, member := range template.EnrollmentMembership.Members {
				if member.SID == expectedSID {
					found = true
				}
			}
		}
		if !found {
			t.Fatal("combined endpoint job silently omitted the expected nested enrollment member")
		}
	}
	count := 0
	for _, service := range result.Inventory.EnrollmentServices {
		if service.Name != "trstctl-A229-CA" {
			continue
		}
		for _, endpoint := range service.Endpoints {
			count++
			if endpoint.Source != "ldap_dns" && endpoint.Source != "configured_and_ldap_dns" {
				t.Fatal("real target lost its provenance")
			}
			if endpoint.Kind == adcs.EndpointWebEnrollment && endpoint.HTTPStatus != 401 {
				t.Fatalf("web endpoint=%+v", endpoint)
			}
			if endpoint.Kind == adcs.EndpointNDES && endpoint.HTTPStatus != 200 {
				t.Fatalf("NDES client endpoint=%+v", endpoint)
			}
			if endpoint.State == adcs.EndpointUnreachable {
				t.Fatal("allowed network target was not reached")
			}
		}
	}
	if count != 4 || len(readAudit()) != before+4 {
		t.Fatalf("actual probes=%d audit_delta=%d", count, len(readAudit())-before)
	}
	wire, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{"fixture-challenge", "fixture-ntlm", "fixture-cookie", "fixture-body-never-evidence"} {
		if bytes.Contains(wire, []byte(canary)) {
			t.Fatalf("HTTP secret/body canary retained: %s", canary)
		}
	}
	defaultOff := intent
	defaultOff.EndpointProbe = nil
	defaultOff.PreviousProbePage = nil
	defaultOff.JobKind = adcs.JobKind
	if defaultOff.NestedGroupsEnabled {
		defaultOff.JobKind = adcs.NestedGroupsJobKind
	}
	defaultOff.EnrollmentEndpoints = nil
	defaultOff.AllowPrivateEndpoint = false
	defaultOff.PrivateEgressCIDRs = nil
	prior := len(readAudit())
	_ = collect(defaultOff)
	if len(readAudit()) != prior {
		t.Fatal("default-off directory read caused HTTP I/O")
	}
	check := func(command ADCSInventoryIntent, targetURL string, want adcs.EnrollmentEndpointState) {
		t.Helper()
		client, err := newADCSEndpointClient(command)
		if err != nil {
			t.Fatal(err)
		}
		defer client.CloseIdleConnections()
		bounded, cancel := context.WithTimeout(t.Context(), adcsDialTimeout)
		defer cancel()
		endpoint := observeEnrollmentEndpoint(bounded, client, adcs.EnrollmentEndpointTarget{EnrollmentService: "trstctl-A229-CA", Kind: adcs.EndpointWebEnrollment, URL: targetURL})
		if endpoint.State != want {
			t.Fatalf("target %s state=%s want=%s", targetURL, endpoint.State, want)
		}
	}
	check(intent, "http://redirect.a229.trstctl.test/certsrv/", adcs.EndpointRedirected)
	denied := intent
	denied.AllowPrivateEndpoint = false
	denied.PrivateEgressCIDRs = nil
	check(denied, "http://ca.a229.trstctl.test/certsrv/", adcs.EndpointUnreachable)
	check(intent, "https://untrusted.a229.trstctl.test/certsrv/", adcs.EndpointUnreachable)
	check(intent, "http://169.254.169.254/certsrv/", adcs.EndpointUnreachable)
	check(intent, "http://127.0.0.1/certsrv/", adcs.EndpointUnreachable)
	elsewhere, err := netsec.ParseRelayEgress([]string{"10.7.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	SetEgressPolicy(elsewhere)
	check(intent, "http://ca.a229.trstctl.test/certsrv/", adcs.EndpointUnreachable)
	SetEgressPolicy(allowed)
	check(intent, "http://oversized.a229.trstctl.test/certsrv/", adcs.EndpointUnreachable)
	for _, entry := range readAudit()[before:] {
		if entry["authorization_present"] != false || entry["cookie_present"] != false || entry["range"] != "bytes=0-0" || (entry["path"] != "/certsrv/" && entry["path"] != "/certsrv/mscep/mscep.dll") {
			t.Fatalf("unsafe request audit=%+v", entry)
		}
	}
	if path := os.Getenv("TRSTCTL_ADCS_PROBE_REPORT"); path != "" {
		if err := os.WriteFile(path, append(wire, '\n'), 0600); err != nil { // #nosec G304,G703 -- operator-selected owned evidence output containing only validated public report fields (CWE-22).
			t.Fatal(err)
		}
	}
	t.Log("Real Samba hostname -> safe HTTP/verified TLS probes passed; redirect, untrusted TLS, private/metadata/loopback/relay egress and header bounds refused; Windows IIS/NDES remain unqualified")
}
