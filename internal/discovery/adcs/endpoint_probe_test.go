// SPDX-License-Identifier: BUSL-1.1
package adcs_test

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"trstctl.com/trstctl/internal/discovery/adcs"
)

func endpointProbeIntent(t *testing.T, enabled bool) adcs.InventoryIntent {
	t.Helper()
	config := map[string]any{"url": "ldaps://dc.corp.example", "configuration_dn": configDN, "bind_dn": "CN=reader," + membershipDomainDN, "password_ref": "secret://adcs/reader", "relay_agent_id": "11111111-1111-4111-8111-111111111111"} // #nosec G101 -- public logical reference fixture, never a credential value (CWE-798).
	if enabled {
		config["endpoint_probe"] = map[string]any{"enabled": true, "dns_suffixes": []string{"corp.example"}}
	}
	raw, _ := json.Marshal(config)
	intent, err := adcs.ResolveInventoryIntent(raw)
	if err != nil {
		t.Fatal(err)
	}
	return intent
}
func TestLDAPEndpointProbePlanUsesOnlyScopedFixedClientPaths(t *testing.T) {
	intent := endpointProbeIntent(t, true)
	if intent.JobKind != adcs.EndpointProbeJobKind {
		t.Fatal("endpoint probing can be silently ignored by an older relay")
	}
	page, err := adcs.PlanEnrollmentEndpointProbes(intent, []adcs.EnrollmentService{{Name: "CORP-CA", DNSName: "CA01.corp.example."}})
	if err != nil {
		t.Fatal(err)
	}
	if page.TotalTargets != 4 || len(page.Targets) != 4 || !page.Complete {
		t.Fatalf("scoped candidate plan=%+v", page)
	}
	seen := map[string]bool{}
	for _, target := range page.Targets {
		parsed, err := url.Parse(target.URL)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Hostname() != "ca01.corp.example" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			t.Fatalf("LDAP hostname escaped its fixed URL: %s", target.URL)
		}
		if parsed.Path != "/certsrv/" && parsed.Path != "/certsrv/mscep/mscep.dll" {
			t.Fatalf("unexpected enrollment path: %s", parsed.Path)
		}
		if target.EnrollmentService != "CORP-CA" || target.Source != "ldap_dns" {
			t.Fatalf("target lost LDAP provenance: %+v", target)
		}
		if strings.Contains(target.URL, "mscep_admin") {
			t.Fatal("automatic probe visited the challenge administration page")
		}
		seen[target.URL] = true
	}
	if len(seen) != 4 {
		t.Fatal("duplicate protocol/path candidates")
	}
}
func TestLDAPEndpointProbeDefaultOffAndExplicitDuplicate(t *testing.T) {
	services := []adcs.EnrollmentService{{Name: "CORP-CA", DNSName: "ca01.corp.example"}}
	intent := endpointProbeIntent(t, false)
	page, err := adcs.PlanEnrollmentEndpointProbes(intent, services)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Targets) != 0 {
		t.Fatal("default-off source generated an HTTP request")
	}
	intent = endpointProbeIntent(t, true)
	intent.EnrollmentEndpoints = []adcs.EnrollmentEndpointTarget{{EnrollmentService: "CORP-CA", Kind: adcs.EndpointWebEnrollment, URL: "https://ca01.corp.example/certsrv/"}}
	page, err = adcs.PlanEnrollmentEndpointProbes(intent, services)
	if err != nil {
		t.Fatal(err)
	}
	if page.TotalTargets != 4 || len(page.Targets) != 4 {
		t.Fatalf("configured/generated duplicate counted twice: %+v", page)
	}
	both := false
	for _, target := range page.Targets {
		if target.URL == intent.EnrollmentEndpoints[0].URL {
			both = target.Source == "configured_and_ldap_dns"
		}
	}
	if !both {
		t.Fatal("deduplication dropped configured or LDAP provenance")
	}
}
func TestLDAPEndpointProbeInvalidOrForeignNamesRemainExplicitlyUnassessed(t *testing.T) {
	intent := endpointProbeIntent(t, true)
	for _, host := range []string{"169.254.169.254", "127.0.0.1", "dc.corp.example@attacker.test", "corp.example.attacker.test", "https://ca.corp.example/", "ca.corp.example:8443", "ca\n.corp.example", "*.corp.example"} {
		t.Run(fmt.Sprintf("%q", host), func(t *testing.T) {
			page, err := adcs.PlanEnrollmentEndpointProbes(intent, []adcs.EnrollmentService{{Name: "CA", DNSName: host}})
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Targets) != 0 || len(page.HostIssues) != 1 || page.Complete {
				t.Fatalf("invalid/out-of-scope LDAP name became complete probes: %+v", page)
			}
		})
	}
}
func TestLDAPEndpointProbePagesAdvanceAndResetAfterDirectoryChanges(t *testing.T) {
	intent := endpointProbeIntent(t, true)
	var services []adcs.EnrollmentService
	for index := range 10 {
		services = append(services, adcs.EnrollmentService{Name: fmt.Sprintf("CA%02d", index), DNSName: fmt.Sprintf("ca%02d.corp.example", index)})
	}
	first, err := adcs.PlanEnrollmentEndpointProbes(intent, services)
	if err != nil {
		t.Fatal(err)
	}
	if first.TotalTargets != 40 || len(first.Targets) != 24 || first.NextOffset != 24 || first.Complete {
		t.Fatalf("large estate lost its remaining candidates: %+v", first)
	}
	intent.PreviousProbePage = &adcs.EndpointProbeCursor{PlanDigest: first.PlanDigest, NextOffset: first.NextOffset}
	second, err := adcs.PlanEnrollmentEndpointProbes(intent, services)
	if err != nil {
		t.Fatal(err)
	}
	if second.Offset != 24 || len(second.Targets) != 16 || second.NextOffset != 0 || second.PlanDigest != first.PlanDigest || second.Complete {
		t.Fatalf("page continuation made a false full-estate claim: %+v", second)
	}
	seen := map[string]bool{}
	for _, target := range first.Targets {
		seen[target.URL] = true
	}
	for _, target := range second.Targets {
		if seen[target.URL] {
			t.Fatal("continuation repeated the prior page")
		}
		seen[target.URL] = true
	}
	if len(seen) != 40 {
		t.Fatal("bounded pages silently omitted a candidate")
	}
	services = append(services, adcs.EnrollmentService{Name: "NewCA", DNSName: "new.corp.example"})
	changed, err := adcs.PlanEnrollmentEndpointProbes(intent, services)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Offset != 0 || changed.PlanDigest == first.PlanDigest {
		t.Fatal("changed directory reused a stale page cursor")
	}
}

func TestLDAPEndpointProbeReportBindsPageProvenanceAndUnassessedTargets(t *testing.T) {
	intent := endpointProbeIntent(t, true)
	intent.ID, intent.SourceID = "run", "source"
	services := []adcs.EnrollmentService{{Name: "CA", DNSName: "ca01.corp.example", AgentRestrictions: adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceUnobserved, Source: "requires_windows_relay"}}}
	page, err := adcs.PlanEnrollmentEndpointProbes(intent, services)
	if err != nil {
		t.Fatal(err)
	}
	services[0].EndpointProbe = page.ServiceCoverage("CA")
	for _, target := range page.Targets {
		services[0].Endpoints = append(services[0].Endpoints, adcs.EnrollmentEndpoint{Kind: target.Kind, URL: target.URL, Source: target.Source, State: adcs.EndpointAuthenticationNeeded, HTTPStatus: 401, Authentication: []string{"Negotiate"}, TLSVerified: strings.HasPrefix(target.URL, "https://"), ExtendedProtection: adcs.EvidenceUnobserved})
	}
	inv := adcs.Inventory{Templates: []adcs.Template{{Name: "User", EKUs: []string{adcs.EKUClientAuth}}}, EnrollmentServices: services, EndpointProbePage: &page}
	good := adcs.InventoryReport{Status: "succeeded", Inventory: inv, Findings: adcs.Findings(inv)}
	if err := adcs.ValidateInventoryReport(intent, good); err != nil {
		t.Fatal(err)
	}
	for name, tamper := range map[string]func(*adcs.InventoryReport){
		"invented hostname": func(r *adcs.InventoryReport) {
			r.Inventory.EnrollmentServices[0].Endpoints[0].URL = "http://attacker.test/certsrv/"
		},
		"omitted candidate": func(r *adcs.InventoryReport) {
			r.Inventory.EnrollmentServices[0].Endpoints = r.Inventory.EnrollmentServices[0].Endpoints[1:]
		},
		"invented provenance":    func(r *adcs.InventoryReport) { r.Inventory.EnrollmentServices[0].Endpoints[0].Source = "configured" },
		"invented complete page": func(r *adcs.InventoryReport) { r.Inventory.EndpointProbePage.TotalTargets++ },
		"missing coverage":       func(r *adcs.InventoryReport) { r.Inventory.EnrollmentServices[0].EndpointProbe = nil },
	} {
		t.Run(name, func(t *testing.T) {
			wire, _ := json.Marshal(good)
			var report adcs.InventoryReport
			if err := json.Unmarshal(wire, &report); err != nil {
				t.Fatal(err)
			}
			tamper(&report)
			report.Findings = adcs.Findings(report.Inventory)
			if err := adcs.ValidateInventoryReport(intent, report); err == nil {
				t.Fatal("altered probe evidence was accepted")
			}
		})
	}
	endpoint := &good.Inventory.EnrollmentServices[0].Endpoints[0]
	endpoint.State = adcs.EndpointNotChecked
	endpoint.NotCheckedReason = "deadline_or_cancellation"
	endpoint.HTTPStatus = 0
	endpoint.Authentication = nil
	endpoint.TLSVerified = false
	good.Findings = adcs.Findings(good.Inventory)
	if err := adcs.ValidateInventoryReport(intent, good); err != nil {
		t.Fatal(err)
	}
	endpoint.HTTPStatus = 200
	good.Findings = adcs.Findings(good.Inventory)
	if err := adcs.ValidateInventoryReport(intent, good); err == nil {
		t.Fatal("unattempted target claimed an HTTP outcome")
	}
}

func TestLDAPEndpointProbeEquivalentConfiguredAuthorityDeduplicates(t *testing.T) {
	intent := endpointProbeIntent(t, true)
	intent.EnrollmentEndpoints = []adcs.EnrollmentEndpointTarget{{EnrollmentService: "CA", Kind: adcs.EndpointWebEnrollment, URL: "https://CA01.corp.example.:443/certsrv/"}}
	page, err := adcs.PlanEnrollmentEndpointProbes(intent, []adcs.EnrollmentService{{Name: "CA", DNSName: "ca01.corp.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if page.TotalTargets != 4 {
		t.Fatalf("equivalent DNS authorities caused duplicate probes: %+v", page.Targets)
	}
	found := false
	for _, target := range page.Targets {
		if target.URL == "https://ca01.corp.example/certsrv/" {
			found = target.Source == "configured_and_ldap_dns"
		}
	}
	if !found {
		t.Fatal("equivalent configured authority lost combined provenance")
	}
}
