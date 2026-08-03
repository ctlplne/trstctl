// SPDX-License-Identifier: MPL-2.0

package adcs_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/discovery/adcs"
)

// AD CS template inventory and posture (epic F1). The value of this epic is not
// that it reads LDAP — it is that it names the COMBINATIONS, because nobody
// spots a domain escalation path by scanning four boolean columns across ninety
// templates.

// fakeDirectory answers searches from a fixture and records what was asked, so a
// test can prove the query is scoped rather than a wildcard sweep.
type fakeDirectory struct {
	byBase map[string][]adcs.Entry
	asked  []string
	attrs  [][]string
	err    error
}

func (f *fakeDirectory) Search(_ context.Context, baseDN, _ string, attributes []string) ([]adcs.Entry, error) {
	f.asked = append(f.asked, baseDN)
	f.attrs = append(f.attrs, attributes)
	if f.err != nil {
		return nil, f.err
	}
	return f.byBase[baseDN], nil
}

const configDN = "CN=Configuration,DC=corp,DC=example"

func directoryWith(templates, services []adcs.Entry) *fakeDirectory {
	base := adcs.PublicKeyServicesRDN + "," + configDN
	return &fakeDirectory{byBase: map[string][]adcs.Entry{
		"CN=Certificate Templates," + base: templates,
		"CN=Enrollment Services," + base:   services,
	}}
}

// TestCollectReadsTemplatesAndBindsThemToPublishingCAs: a dangerous template
// nobody publishes is a latent risk an operator can fix calmly; one an issuing
// CA offers is not. The inventory has to distinguish them.
func TestCollectReadsTemplatesAndBindsThemToPublishingCAs(t *testing.T) {
	dir := directoryWith(
		[]adcs.Entry{
			{DN: "CN=WebServer,...", Attributes: map[string][]string{
				"cn":                            {"WebServer"},
				"displayName":                   {"Web Server"},
				"msPKI-Template-Schema-Version": {"4"},
				"pKIExtendedKeyUsage":           {"1.3.6.1.5.5.7.3.1"},
			}},
			{DN: "CN=Unpublished,...", Attributes: map[string][]string{
				"cn":                            {"Unpublished"},
				"msPKI-Template-Schema-Version": {"2"},
				"pKIExtendedKeyUsage":           {"1.3.6.1.5.5.7.3.2"},
			}},
		},
		[]adcs.Entry{
			{DN: "CN=CORP-CA,...", Attributes: map[string][]string{
				"cn":                   {"CORP-CA"},
				"dNSHostName":          {"ca01.corp.example"},
				"certificateTemplates": {"WebServer"},
			}},
		},
	)
	inv, err := adcs.Collect(context.Background(), dir, configDN)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(inv.Templates) != 2 || len(inv.EnrollmentServices) != 1 {
		t.Fatalf("inventory = %d templates / %d services, want 2 / 1", len(inv.Templates), len(inv.EnrollmentServices))
	}
	byName := map[string]adcs.Template{}
	for _, tpl := range inv.Templates {
		byName[tpl.Name] = tpl
	}
	if got := byName["WebServer"].PublishedBy; !reflect.DeepEqual(got, []string{"CORP-CA"}) {
		t.Errorf("WebServer PublishedBy = %v, want [CORP-CA]", got)
	}
	if len(byName["Unpublished"].PublishedBy) != 0 {
		t.Errorf("an unpublished template reports publishers: %v", byName["Unpublished"].PublishedBy)
	}
}

// TestCollectAsksForNamedAttributesOnly: an inventory tool should not pull
// attributes it has no reason to hold, and a wildcard against a domain
// controller is both slower and more than was asked for.
func TestCollectAsksForNamedAttributesOnly(t *testing.T) {
	dir := directoryWith(nil, nil)
	if _, err := adcs.Collect(context.Background(), dir, configDN); err != nil {
		t.Fatalf("collect: %v", err)
	}
	for _, attrs := range dir.attrs {
		if len(attrs) == 0 {
			t.Fatal("a search requested every attribute; the query must name what it uses")
		}
		for _, a := range attrs {
			if a == "*" || a == "" {
				t.Fatalf("a search requested %q", a)
			}
		}
	}
	// Both containers are scoped under Public Key Services, not searched from
	// the naming context root.
	for _, base := range dir.asked {
		if !strings.Contains(base, adcs.PublicKeyServicesRDN) {
			t.Errorf("search base %q is not scoped to the Public Key Services container", base)
		}
	}
}

// TestSearcherIsReadOnly is the structural guarantee. An inventory tool pointed
// at a domain controller must be incapable of changing one, not merely careful.
func TestSearcherIsReadOnly(t *testing.T) {
	typ := reflect.TypeOf((*adcs.Searcher)(nil)).Elem()
	if typ.NumMethod() != 1 {
		t.Fatalf("the directory interface has %d methods; it must have exactly one, and that one must read", typ.NumMethod())
	}
	if name := typ.Method(0).Name; name != "Search" {
		t.Fatalf("the directory interface's only method is %q, want Search", name)
	}
}

// TestCollectFailsRatherThanReportingAnEmptyDomain: an unreachable directory
// reported as "no templates" would tell an operator their AD CS estate is clean.
func TestCollectFailsRatherThanReportingAnEmptyDomain(t *testing.T) {
	dir := directoryWith(nil, nil)
	dir.err = errors.New("LDAP result code 8: strong auth required")
	if _, err := adcs.Collect(context.Background(), dir, configDN); err == nil {
		t.Fatal("an unreachable directory reported success")
	}
	if _, err := adcs.Collect(context.Background(), directoryWith(nil, nil), ""); err == nil {
		t.Fatal("collect ran with no configuration naming context; guessing one gets multi-domain forests wrong")
	}
}

// TestESC1IsFoundOnlyWhenEveryElementIsPresent is the heart of the epic. Each
// element of the combination is necessary; reporting the flags separately would
// have surfaced none of this and all of the noise.
func TestESC1IsFoundOnlyWhenEveryElementIsPresent(t *testing.T) {
	esc1 := adcs.Template{
		Name: "VulnTemplate", SchemaVersion: 4,
		EnrolleeSuppliesSubject: true,
		EKUs:                    []string{adcs.EKUClientAuth},
		PublishedBy:             []string{"CORP-CA"},
	}
	if !hasFinding(adcs.Findings(adcs.Inventory{Templates: []adcs.Template{esc1}}), "ADCS-ESC1") {
		t.Fatal("the canonical ESC1 combination was not found")
	}

	// Manager approval interrupts it: no longer critical, and reported as the
	// weaker finding instead so an operator sees the interim state honestly.
	approved := esc1
	approved.RequiresManagerApproval = true
	got := adcs.Findings(adcs.Inventory{Templates: []adcs.Template{approved}})
	if hasFinding(got, "ADCS-ESC1") {
		t.Error("ESC1 reported despite manager approval")
	}
	if !hasFinding(got, "ADCS-SUPPLIES-SUBJECT-APPROVED") {
		t.Error("an approved supplies-subject template produced no finding at all")
	}

	// A server-auth-only template cannot impersonate.
	serverOnly := esc1
	serverOnly.EKUs = []string{"1.3.6.1.5.5.7.3.1"}
	if hasFinding(adcs.Findings(adcs.Inventory{Templates: []adcs.Template{serverOnly}}), "ADCS-ESC1") {
		t.Error("ESC1 reported for a template that cannot authenticate")
	}

	// And no supplies-subject at all is clean on this check.
	fixed := esc1
	fixed.EnrolleeSuppliesSubject = false
	if hasFinding(adcs.Findings(adcs.Inventory{Templates: []adcs.Template{fixed}}), "ADCS-ESC1") {
		t.Error("ESC1 reported for a template whose subject the CA builds")
	}
}

// TestNoEKUCountsAsAuthentication: an empty EKU list is unrestricted, not
// harmless. Treating it as harmless is the mistake worth not making.
func TestNoEKUCountsAsAuthentication(t *testing.T) {
	unrestricted := adcs.Template{
		Name: "Unrestricted", SchemaVersion: 2,
		EnrolleeSuppliesSubject: true,
	}
	if !unrestricted.AllowsClientAuthentication() {
		t.Fatal("a template with no EKU restriction was treated as unable to authenticate")
	}
	got := adcs.Findings(adcs.Inventory{Templates: []adcs.Template{unrestricted}})
	if !hasFinding(got, "ADCS-ESC1") {
		t.Error("an unrestricted supplies-subject template did not produce ESC1")
	}
	if !hasFinding(got, "ADCS-NO-EKU") {
		t.Error("an unrestricted template produced no EKU finding")
	}
}

// TestFindingsAreActionable: every finding must say what an attacker can do and
// what specific change removes it. A posture finding an operator cannot act on
// is a complaint.
func TestFindingsAreActionable(t *testing.T) {
	inv := adcs.Inventory{Templates: []adcs.Template{
		{Name: "A", SchemaVersion: 1, EnrolleeSuppliesSubject: true, EnrolleeSuppliesSAN: true,
			ExportableKey: true, EKUs: []string{adcs.EKUAnyPurpose}, PublishedBy: []string{"CA"}},
	}}
	findings := adcs.Findings(inv)
	if len(findings) == 0 {
		t.Fatal("a template with every dangerous property produced no findings")
	}
	for _, f := range findings {
		if len(f.Summary) < 40 {
			t.Errorf("%s summary is too thin to triage: %q", f.ID, f.Summary)
		}
		if len(f.Remediation) < 40 {
			t.Errorf("%s has no actionable remediation: %q", f.ID, f.Remediation)
		}
		if f.Template != "A" {
			t.Errorf("%s names template %q", f.ID, f.Template)
		}
		if !f.Published {
			t.Errorf("%s does not report that a CA publishes this template", f.ID)
		}
	}
	// Most severe first, so the list reads top-down.
	if findings[0].Severity != adcs.SeverityCritical {
		t.Errorf("findings are not severity-ordered; first is %s", findings[0].Severity)
	}
}

func hasFinding(findings []adcs.Finding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

// TestHardenedTemplatesProduceNoFindings is F3's acceptance and the harder half
// of it. A rule that fires on a vulnerable template is easy; a rule set that
// stays SILENT on a hardened one is what makes the findings worth reading,
// because the first false positive destroys an operator's trust in every true
// one that follows.
func TestHardenedTemplatesProduceNoFindings(t *testing.T) {
	hardened := []adcs.Template{
		{
			// The ordinary web server template: the CA builds the subject, it
			// authenticates servers rather than users, and its key stays put.
			Name: "WebServerHardened", SchemaVersion: 4,
			EKUs:        []string{"1.3.6.1.5.5.7.3.1"},
			PublishedBy: []string{"CORP-CA"},
		},
		{
			// A user authentication template done correctly: supplies-subject
			// is off, so the CA names the requester from the directory.
			Name: "UserAuthHardened", SchemaVersion: 4,
			EKUs:        []string{adcs.EKUClientAuth},
			PublishedBy: []string{"CORP-CA"},
		},
		{
			// Code signing, non-exportable, no authentication purpose.
			Name: "CodeSigning", SchemaVersion: 3,
			EKUs: []string{"1.3.6.1.5.5.7.3.3"},
		},
	}
	if findings := adcs.Findings(adcs.Inventory{Templates: hardened}); len(findings) != 0 {
		t.Fatalf("hardened templates produced %d findings, want none: %+v", len(findings), findings)
	}
}

// TestEnrollmentAgentIsItsOwnFinding: an enrollment agent can request on behalf
// of ANY principal, which is a different and worse primitive than impersonating
// one account — and it has a different remediation.
func TestEnrollmentAgentIsItsOwnFinding(t *testing.T) {
	agent := adcs.Template{
		Name: "EnrollmentAgent", SchemaVersion: 4,
		EKUs:        []string{adcs.EKUCertificateRequestAgent},
		PublishedBy: []string{"CORP-CA"},
	}
	got := adcs.Findings(adcs.Inventory{Templates: []adcs.Template{agent}})
	if !hasFinding(got, "ADCS-ESC3-AGENT") {
		t.Fatalf("an unapproved enrollment-agent template produced no ESC3 finding: %+v", got)
	}

	approved := agent
	approved.RequiresManagerApproval = true
	gotApproved := adcs.Findings(adcs.Inventory{Templates: []adcs.Template{approved}})
	if hasFinding(gotApproved, "ADCS-ESC3-AGENT") {
		t.Error("ESC3 reported despite manager approval")
	}
	// Approval does not make it uninteresting: the control now rests entirely
	// on whoever approves, and the CA's agent restrictions.
	if !hasFinding(gotApproved, "ADCS-ESC3-AGENT-APPROVED") {
		t.Error("an approved enrollment-agent template produced no finding at all")
	}
}

// TestEveryFindingCarriesFalsifiableEvidence is F3's evidence requirement. A
// posture finding an operator cannot check against their own console is an
// assertion taken on faith; one that names the attributes and values read is
// falsifiable, which is what makes it worth acting on.
func TestEveryFindingCarriesFalsifiableEvidence(t *testing.T) {
	inv := adcs.Inventory{Templates: []adcs.Template{
		{Name: "Everything", SchemaVersion: 1, EnrolleeSuppliesSubject: true,
			EnrolleeSuppliesSAN: true, ExportableKey: true,
			EKUs:        []string{adcs.EKUAnyPurpose, adcs.EKUCertificateRequestAgent},
			PublishedBy: []string{"CORP-CA"}},
		{Name: "Approved", SchemaVersion: 4, EnrolleeSuppliesSubject: true,
			RequiresManagerApproval: true, EKUs: []string{adcs.EKUClientAuth}},
		{Name: "NoEKU", SchemaVersion: 2},
	}}
	findings := adcs.Findings(inv)
	if len(findings) == 0 {
		t.Fatal("no findings to check")
	}
	for _, f := range findings {
		if len(f.Evidence) == 0 {
			t.Errorf("%s on %s carries no evidence; an operator cannot check it", f.ID, f.Template)
			continue
		}
		for _, ev := range f.Evidence {
			if ev.Attribute == "" || ev.Observed == "" {
				t.Errorf("%s on %s has an empty evidence reference %+v", f.ID, f.Template, ev)
			}
		}
	}
}
