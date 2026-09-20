// SPDX-License-Identifier: BUSL-1.1

package adcs_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
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
	asked  []adcs.SearchRequest
	err    error
}

func (f *fakeDirectory) Search(_ context.Context, request adcs.SearchRequest) ([]adcs.Entry, error) {
	f.asked = append(f.asked, request)
	if f.err != nil {
		return nil, f.err
	}
	return f.byBase[request.BaseDN], nil
}

const configDN = "CN=Configuration,DC=corp,DC=example"

func directoryWith(templates, services []adcs.Entry) *fakeDirectory {
	for i := range templates {
		if templates[i].BinaryAttributes == nil {
			templates[i].BinaryAttributes = map[string][][]byte{}
		}
		if len(templates[i].BinaryAttributes["nTSecurityDescriptor"]) == 0 {
			templates[i].BinaryAttributes["nTSecurityDescriptor"] = [][]byte{securityDescriptor()}
		}
	}
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
				"cn":                       {"CORP-CA"},
				"dNSHostName":              {"ca01.corp.example"},
				"certificateTemplates":     {"WebServer"},
				"msPKI-Enrollment-Servers": {"0\n0\nhttps://ca01.corp.example/CES_Kerberos/service.svc"},
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
	service := inv.EnrollmentServices[0]
	if !reflect.DeepEqual(service.EnrollmentWebServices, []string{"https://ca01.corp.example/CES_Kerberos/service.svc"}) ||
		service.AgentRestrictions.State != adcs.EvidenceUnobserved {
		t.Fatalf("enrollment service lost CES/closed CA-policy evidence: %+v", service)
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
	for _, request := range dir.asked {
		attrs := request.Attributes
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
	for _, request := range dir.asked {
		if !strings.Contains(request.BaseDN, adcs.PublicKeyServicesRDN) {
			t.Errorf("search base %q is not scoped to the Public Key Services container", request.BaseDN)
		}
		if request.MaxEntries <= 0 {
			t.Errorf("search %q has no entry bound", request.BaseDN)
		}
	}
	if len(dir.asked) != 2 {
		t.Fatalf("search count = %d, want template and enrollment-service reads", len(dir.asked))
	}
	if !dir.asked[0].DACLOnly || dir.asked[1].DACLOnly {
		t.Fatalf("DACL controls = template:%v service:%v, want true/false", dir.asked[0].DACLOnly, dir.asked[1].DACLOnly)
	}
	if !reflect.DeepEqual(dir.asked[0].Attributes[len(dir.asked[0].Attributes)-1:], []string{"nTSecurityDescriptor"}) {
		t.Fatalf("template attributes omit the security descriptor: %v", dir.asked[0].Attributes)
	}
}

// TestCollectDecodesEnrollmentRightsFromTheTemplateDACL is AUD-35's security
// fact. An Enroll object ACE and a generic-all ACE grant enrollment; an object
// ACE for a different extended right does not. A deny for the exact same SID
// wins over its later allow, so the panel never calls that trustee granted.
func TestCollectDecodesEnrollmentRightsFromTheTemplateDACL(t *testing.T) {
	const (
		allowedSID = "S-1-5-21-111-222-333-1001"
		genericSID = "S-1-5-11"
		deniedSID  = "S-1-5-21-111-222-333-1002"
		otherSID   = "S-1-5-21-111-222-333-1003"
	)
	descriptor := securityDescriptor(
		objectACE(0x05, 0x00000100, enrollmentGUIDBytes(), sidBytes(allowedSID)),
		allowACE(0x10000000, sidBytes(genericSID)),
		objectACE(0x06, 0x00000100, enrollmentGUIDBytes(), sidBytes(deniedSID)),
		objectACE(0x05, 0x00000100, enrollmentGUIDBytes(), sidBytes(deniedSID)),
		objectACE(0x05, 0x00000100, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, sidBytes(otherSID)),
	)
	dir := directoryWith([]adcs.Entry{{
		DN: "CN=UserAuth,...",
		Attributes: map[string][]string{
			"cn":                  {"UserAuth"},
			"pKIExtendedKeyUsage": {adcs.EKUClientAuth},
		},
		BinaryAttributes: map[string][][]byte{"nTSecurityDescriptor": {descriptor}},
	}}, nil)

	inv, err := adcs.Collect(context.Background(), dir, configDN)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(inv.Templates) != 1 {
		t.Fatalf("templates = %d, want one", len(inv.Templates))
	}
	want := []string{genericSID, allowedSID}
	if got := inv.Templates[0].EnrollmentPrincipals; !reflect.DeepEqual(got, want) {
		t.Fatalf("enrollment principals = %v, want %v", got, want)
	}
	encoded := string(mustJSON(t, inv))
	if strings.Contains(encoded, string(descriptor)) || strings.Contains(encoded, "nTSecurityDescriptor") {
		t.Fatal("raw security descriptor crossed the normalized inventory boundary")
	}
}

func TestCollectRefusesMalformedEnrollmentACLInsteadOfClaimingNobodyCanEnroll(t *testing.T) {
	dir := directoryWith([]adcs.Entry{{
		DN: "CN=Broken,...", Attributes: map[string][]string{"cn": {"Broken"}},
		BinaryAttributes: map[string][][]byte{"nTSecurityDescriptor": {{1, 2, 3}}},
	}}, nil)
	if _, err := adcs.Collect(context.Background(), dir, configDN); err == nil {
		t.Fatal("malformed ACL became an empty enrollment-principal list")
	}
}

func TestEnrollmentACLRefusesTrailingBytesAfterTrusteeSID(t *testing.T) {
	ace := allowACE(0x10000000, sidBytes("S-1-5-11"))
	ace = append(ace, 0xde, 0xad)
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace))) // #nosec G115 -- the fixed malformed fixture is below MaxUint16 (CWE-190).
	if _, err := adcs.EnrollmentPrincipalsFromSecurityDescriptor(securityDescriptor(ace)); err == nil {
		t.Fatal("trailing bytes after a standard ACE trustee SID were silently accepted")
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func enrollmentGUIDBytes() []byte {
	return []byte{0x68, 0xc9, 0x10, 0x0e, 0xfb, 0x78, 0xd2, 0x11, 0x90, 0xd4, 0x00, 0xc0, 0x4f, 0x79, 0xdc, 0x55}
}

func sidBytes(text string) []byte {
	parts := strings.Split(strings.TrimPrefix(text, "S-"), "-")
	if len(parts) < 2 {
		panic("bad test SID")
	}
	revision, _ := strconv.ParseUint(parts[0], 10, 8)
	authority, _ := strconv.ParseUint(parts[1], 10, 48)
	out := make([]byte, 8+4*(len(parts)-2))
	out[0], out[1] = byte(revision), byte(len(parts)-2) // #nosec G115 -- test SID inputs have at most 255 sub-authorities (CWE-190).
	for i := 0; i < 6; i++ {
		out[7-i] = byte(authority) // #nosec G115 -- ParseUint limits authority to 48 bits and this loop emits one byte at a time (CWE-190).
		authority >>= 8
	}
	for i, part := range parts[2:] {
		value, _ := strconv.ParseUint(part, 10, 32)
		binary.LittleEndian.PutUint32(out[8+i*4:], uint32(value))
	}
	return out
}

func allowACE(mask uint32, sid []byte) []byte {
	out := make([]byte, 8+len(sid))
	out[0] = 0x00
	binary.LittleEndian.PutUint16(out[2:4], uint16(len(out))) // #nosec G115 -- deterministic test SIDs keep the ACE below MaxUint16 (CWE-190).
	binary.LittleEndian.PutUint32(out[4:8], mask)
	copy(out[8:], sid)
	return out
}

func objectACE(aceType byte, mask uint32, objectGUID, sid []byte) []byte {
	out := make([]byte, 12+len(objectGUID)+len(sid))
	out[0] = aceType
	binary.LittleEndian.PutUint16(out[2:4], uint16(len(out))) // #nosec G115 -- deterministic test SIDs keep the object ACE below MaxUint16 (CWE-190).
	binary.LittleEndian.PutUint32(out[4:8], mask)
	binary.LittleEndian.PutUint32(out[8:12], 0x1)
	copy(out[12:], objectGUID)
	copy(out[12+len(objectGUID):], sid)
	return out
}

func securityDescriptor(aces ...[]byte) []byte {
	aclSize := 8
	for _, ace := range aces {
		aclSize += len(ace)
	}
	out := make([]byte, 20+aclSize)
	out[0] = 1
	binary.LittleEndian.PutUint16(out[2:4], 0x8004)
	binary.LittleEndian.PutUint32(out[16:20], 20)
	acl := out[20:]
	acl[0] = 4
	binary.LittleEndian.PutUint16(acl[2:4], uint16(aclSize))
	binary.LittleEndian.PutUint16(acl[4:6], uint16(len(aces))) // #nosec G115 -- test call sites pass a bounded literal ACE set (CWE-190).
	offset := 8
	for _, ace := range aces {
		copy(acl[offset:], ace)
		offset += len(ace)
	}
	return out
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
		EnrollmentPrincipals:    []string{"S-1-5-11"},
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

// TestESC1RequiresObservedLowPrivilegeEnrollmentAUD37 closes the rule/input
// mismatch from the audit. Supplies-subject is not a domain escalation path for
// "anyone" unless the observed DACL actually names a broad/low-privileged
// trustee. Custom groups are not guessed low privilege from their RID.
func TestESC1RequiresObservedLowPrivilegeEnrollmentAUD37(t *testing.T) {
	base := adcs.Template{
		Name: "UserAuth", SchemaVersion: 4, EnrolleeSuppliesSubject: true,
		EKUs: []string{adcs.EKUClientAuth}, PublishedBy: []string{"CORP-CA"},
	}
	for name, principals := range map[string][]string{
		"everyone":            {"S-1-1-0"},
		"authenticated-users": {"S-1-5-11"},
		"builtin-users":       {"S-1-5-32-545"},
		"domain-users":        {"S-1-5-21-111-222-333-513"},
		"domain-computers":    {"S-1-5-21-111-222-333-515"},
	} {
		t.Run(name, func(t *testing.T) {
			template := base
			template.EnrollmentPrincipals = principals
			findings := adcs.Findings(adcs.Inventory{Templates: []adcs.Template{template}})
			finding := findingByID(findings, "ADCS-ESC1")
			if finding == nil || !evidenceContains(finding.Evidence, "nTSecurityDescriptor enrollment trustees", principals[0]) {
				t.Fatalf("low-privilege trustee %v did not produce falsifiable ESC1: %+v", principals, findings)
			}
		})
	}
	for name, principals := range map[string][]string{
		"no-grant":      {},
		"custom-group":  {"S-1-5-21-111-222-333-1001"},
		"domain-admins": {"S-1-5-21-111-222-333-512"},
	} {
		t.Run(name, func(t *testing.T) {
			template := base
			template.EnrollmentPrincipals = principals
			if findings := adcs.Findings(adcs.Inventory{Templates: []adcs.Template{template}}); hasFinding(findings, "ADCS-ESC1") {
				t.Fatalf("trustees %v were guessed low privilege: %+v", principals, findings)
			}
		})
	}
}

// TestEnrollmentServiceRulesUseClosedLiveEvidenceAUD37 proves three distinct
// facts stay distinct: CES publication, live legacy IIS probes, and CA-side
// Enrollment Agent Restrictions. Unreachable/unobserved never becomes safe.
func TestEnrollmentServiceRulesUseClosedLiveEvidenceAUD37(t *testing.T) {
	vulnerable := adcs.EnrollmentService{
		Name: "CORP-CA", DNSName: "ca01.corp.example",
		EnrollmentWebServices: []string{"http://ca01.corp.example/CES_Kerberos/service.svc"},
		AgentRestrictions:     adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceDisabled, Source: "windows_ca_policy"},
		Endpoints: []adcs.EnrollmentEndpoint{
			{Kind: adcs.EndpointWebEnrollment, URL: "http://webenroll.corp.example/certsrv/", State: adcs.EndpointAuthenticationNeeded, HTTPStatus: 401, Authentication: []string{"Negotiate", "NTLM"}, ExtendedProtection: adcs.EvidenceDisabled},
			{Kind: adcs.EndpointNDESAdmin, URL: "https://ndes.corp.example/certsrv/mscep_admin/", State: adcs.EndpointAnonymousAccess, HTTPStatus: 200, TLSVerified: true, ExtendedProtection: adcs.EvidenceUnobserved},
		},
	}
	findings := adcs.Findings(adcs.Inventory{EnrollmentServices: []adcs.EnrollmentService{vulnerable}})
	for _, id := range []string{"ADCS-CES-PLAINTEXT", "ADCS-WEB-ENROLLMENT-PLAINTEXT", "ADCS-WEB-ENROLLMENT-EPA-DISABLED", "ADCS-NDES-ADMIN-ANONYMOUS"} {
		finding := findingByID(findings, id)
		if finding == nil || finding.ResourceKind != "enrollment_service" || finding.Resource != "CORP-CA" || len(finding.Evidence) == 0 {
			t.Fatalf("service rule %s missing exact resource/evidence: %+v", id, findings)
		}
	}

	hardened := adcs.EnrollmentService{
		Name:                  "CORP-CA",
		EnrollmentWebServices: []string{"https://ca01.corp.example/CES_Kerberos/service.svc"},
		AgentRestrictions:     adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceEnabled, Source: "windows_ca_policy"},
		Endpoints: []adcs.EnrollmentEndpoint{
			{Kind: adcs.EndpointWebEnrollment, URL: "https://webenroll.corp.example/certsrv/", State: adcs.EndpointAuthenticationNeeded, HTTPStatus: 401, Authentication: []string{"Negotiate"}, TLSVerified: true, ExtendedProtection: adcs.EvidenceEnabled},
			{Kind: adcs.EndpointNDESAdmin, URL: "https://ndes.corp.example/certsrv/mscep_admin/", State: adcs.EndpointAuthenticationNeeded, HTTPStatus: 401, TLSVerified: true, ExtendedProtection: adcs.EvidenceEnabled},
		},
	}
	if got := adcs.Findings(adcs.Inventory{EnrollmentServices: []adcs.EnrollmentService{hardened}}); len(got) != 0 {
		t.Fatalf("hardened enrollment service produced false alarms: %+v", got)
	}
}

// TestNoEKUCountsAsAuthentication: an empty EKU list is unrestricted, not
// harmless. Treating it as harmless is the mistake worth not making.
func TestNoEKUCountsAsAuthentication(t *testing.T) {
	unrestricted := adcs.Template{
		Name: "Unrestricted", SchemaVersion: 2,
		EnrolleeSuppliesSubject: true,
		EnrollmentPrincipals:    []string{"S-1-5-21-111-222-333-513"},
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
			ExportableKey: true, EKUs: []string{adcs.EKUAnyPurpose}, EnrollmentPrincipals: []string{"S-1-1-0"}, PublishedBy: []string{"CA"}},
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
	return findingByID(findings, id) != nil
}

func findingByID(findings []adcs.Finding, id string) *adcs.Finding {
	for _, f := range findings {
		if f.ID == id {
			finding := f
			return &finding
		}
	}
	return nil
}

func evidenceContains(evidence []adcs.EvidenceRef, attribute, fragment string) bool {
	for _, ref := range evidence {
		if ref.Attribute == attribute && strings.Contains(ref.Observed, fragment) {
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
	service := adcs.EnrollmentService{Name: "CORP-CA", AgentRestrictions: adcs.EnrollmentAgentRestrictions{
		State: adcs.EvidenceDisabled, Source: "windows_ca_policy",
	}}
	got := adcs.Findings(adcs.Inventory{Templates: []adcs.Template{agent}, EnrollmentServices: []adcs.EnrollmentService{service}})
	if !hasFinding(got, "ADCS-ESC3-AGENT") {
		t.Fatalf("an unapproved enrollment-agent template produced no ESC3 finding: %+v", got)
	}

	approved := agent
	approved.RequiresManagerApproval = true
	gotApproved := adcs.Findings(adcs.Inventory{Templates: []adcs.Template{approved}, EnrollmentServices: []adcs.EnrollmentService{service}})
	if hasFinding(gotApproved, "ADCS-ESC3-AGENT") {
		t.Error("ESC3 reported despite manager approval")
	}
	// Approval does not make it uninteresting: the control now rests entirely
	// on whoever approves, and the CA's agent restrictions.
	if !hasFinding(gotApproved, "ADCS-ESC3-AGENT-APPROVED") {
		t.Error("an approved enrollment-agent template produced no finding at all")
	}
}

func TestEnrollmentAgentRestrictionEvidenceNeverDefaultsSafeAUD37(t *testing.T) {
	agent := adcs.Template{
		Name: "EnrollmentAgent", SchemaVersion: 4,
		EKUs: []string{adcs.EKUCertificateRequestAgent}, PublishedBy: []string{"CORP-CA"},
	}
	unobserved := adcs.Findings(adcs.Inventory{Templates: []adcs.Template{agent}})
	if hasFinding(unobserved, "ADCS-ESC3-AGENT") || !hasFinding(unobserved, "ADCS-ESC3-RESTRICTIONS-UNOBSERVED") {
		t.Fatalf("unobserved CA policy became a vulnerable/safe guess: %+v", unobserved)
	}
	enabled := adcs.EnrollmentService{Name: "CORP-CA", AgentRestrictions: adcs.EnrollmentAgentRestrictions{
		State: adcs.EvidenceEnabled, Source: "windows_ca_policy",
	}}
	if findings := adcs.Findings(adcs.Inventory{Templates: []adcs.Template{agent}, EnrollmentServices: []adcs.EnrollmentService{enabled}}); len(findings) != 0 {
		t.Fatalf("observed enabled agent restrictions produced a false alarm: %+v", findings)
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
			EKUs:                 []string{adcs.EKUAnyPurpose, adcs.EKUCertificateRequestAgent},
			EnrollmentPrincipals: []string{"S-1-5-11"},
			PublishedBy:          []string{"CORP-CA"}},
		{Name: "Approved", SchemaVersion: 4, EnrolleeSuppliesSubject: true,
			RequiresManagerApproval: true, EKUs: []string{adcs.EKUClientAuth}},
		{Name: "NoEKU", SchemaVersion: 2},
	}, EnrollmentServices: []adcs.EnrollmentService{{
		Name: "CORP-CA", AgentRestrictions: adcs.EnrollmentAgentRestrictions{State: adcs.EvidenceDisabled, Source: "windows_ca_policy"},
	}}}
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

// TestDriftIsSemanticNotTextual is F2's point. "msPKI-Certificate-Name-Flag
// changed from 0 to 1" is technically a diff and tells nobody anything; what an
// operator needs is that somebody turned on supplies-subject.
func TestDriftIsSemanticNotTextual(t *testing.T) {
	before := []adcs.Template{{
		Name: "UserAuth", SchemaVersion: 4,
		RequiresManagerApproval: true,
		EKUs:                    []string{adcs.EKUClientAuth},
		PublishedBy:             []string{"CORP-CA"},
	}}
	after := []adcs.Template{{
		Name: "UserAuth", SchemaVersion: 4,
		EnrolleeSuppliesSubject: true,
		RequiresManagerApproval: false,
		EKUs:                    []string{adcs.EKUClientAuth},
		PublishedBy:             []string{"CORP-CA"},
	}}
	drift := adcs.DiffTemplates(before, after)
	if !drift.Worsened() {
		t.Fatal("a template that gained supplies-subject and lost manager approval did not read as worse")
	}
	var sawSupplies, sawApproval bool
	for _, c := range drift.Changes {
		if c.Direction != adcs.DriftWorse {
			continue
		}
		if strings.Contains(c.Change, "supply their own subject") {
			sawSupplies = true
		}
		if strings.Contains(c.Change, "Manager approval was REMOVED") {
			sawApproval = true
		}
		// The audit trail behind the sentence: a claim about someone's
		// directory they cannot check is one they will not act on.
		if c.Attribute == "" || c.Before == "" || c.After == "" {
			t.Errorf("change %q carries no before/after audit trail", c.Change)
		}
	}
	if !sawSupplies || !sawApproval {
		t.Fatalf("the two security-relevant changes were not both reported: %+v", drift.Changes)
	}
}

// TestHardeningDoesNotAlert: an operator who just fixed a template does not need
// waking. Worsened() is the gate, and better changes are recorded without it.
func TestHardeningDoesNotAlert(t *testing.T) {
	before := []adcs.Template{{
		Name: "Vuln", SchemaVersion: 4, EnrolleeSuppliesSubject: true,
		ExportableKey: true, EKUs: []string{adcs.EKUClientAuth},
	}}
	after := []adcs.Template{{
		Name: "Vuln", SchemaVersion: 4,
		RequiresManagerApproval: true, EKUs: []string{adcs.EKUClientAuth},
	}}
	drift := adcs.DiffTemplates(before, after)
	if drift.Worsened() {
		t.Fatal("hardening a template alerted as drift")
	}
	if len(drift.Changes) == 0 {
		t.Fatal("hardening produced no recorded change at all; the timeline needs it even though the alert does not")
	}
	for _, c := range drift.Changes {
		if c.Direction == adcs.DriftWorse {
			t.Errorf("hardening change reported as worse: %q", c.Change)
		}
	}
}

// TestEnrollmentTrusteeDriftCarriesBeforeAfterAUD36 proves that a DACL change
// is translated into the operator fact that matters. The raw security
// descriptor never enters the drift record; canonical SIDs do, so the operator
// can see exactly who gained or lost enrollment access.
func TestEnrollmentTrusteeDriftCarriesBeforeAfterAUD36(t *testing.T) {
	before := []adcs.Template{{
		Name: "UserAuth", EnrollmentPrincipals: []string{"S-1-5-11"},
	}}
	after := []adcs.Template{{
		Name: "UserAuth", EnrollmentPrincipals: []string{"S-1-5-11", "S-1-5-21-111-222-333-1001"},
	}}
	drift := adcs.DiffTemplates(before, after)
	if !drift.Worsened() || len(drift.Changes) != 1 {
		t.Fatalf("trustee expansion = %+v, want one worsening change", drift)
	}
	change := drift.Changes[0]
	if change.Attribute != "nTSecurityDescriptor enrollment trustees" ||
		change.Before != "S-1-5-11" ||
		change.After != "S-1-5-11, S-1-5-21-111-222-333-1001" ||
		!strings.Contains(change.Change, "gained enrollment access") {
		t.Fatalf("trustee expansion lost semantic before/after evidence: %+v", change)
	}

	back := adcs.DiffTemplates(after, before)
	if back.Worsened() || len(back.Changes) != 1 || back.Changes[0].Direction != adcs.DriftBetter {
		t.Fatalf("trustee removal = %+v, want one recorded improvement without an alert", back)
	}
}

// TestFirstSweepIsNotDrift: reporting an entire estate as "added" the first time
// anyone looks would bury the real change that comes next under ninety
// notifications.
func TestFirstSweepIsNotDrift(t *testing.T) {
	current := []adcs.Template{
		{Name: "A", EnrolleeSuppliesSubject: true, EKUs: []string{adcs.EKUClientAuth}},
		{Name: "B", EKUs: []string{"1.3.6.1.5.5.7.3.1"}},
	}
	drift := adcs.DiffTemplates(nil, current)
	if len(drift.Changes) != 0 || len(drift.Lifecycle) != 0 {
		t.Fatalf("a first sweep produced drift: %+v", drift)
	}
	if drift.Worsened() {
		t.Fatal("a first sweep alerted")
	}
}

// TestPublishingADangerousTemplateIsDrift: no attribute of the template moved,
// but a latent risk became an offered one.
func TestPublishingADangerousTemplateIsDrift(t *testing.T) {
	vuln := adcs.Template{
		Name: "Vuln", SchemaVersion: 4, EnrolleeSuppliesSubject: true,
		EKUs: []string{adcs.EKUClientAuth}, EnrollmentPrincipals: []string{"S-1-5-11"},
	}
	published := vuln
	published.PublishedBy = []string{"CORP-CA"}

	drift := adcs.DiffTemplates([]adcs.Template{vuln}, []adcs.Template{published})
	if !drift.Worsened() {
		t.Fatal("publishing a template that carries findings did not read as worse")
	}
	// And unpublishing it is an improvement, not a new alarm.
	back := adcs.DiffTemplates([]adcs.Template{published}, []adcs.Template{vuln})
	if back.Worsened() {
		t.Fatal("unpublishing a dangerous template alerted")
	}
}

// TestNewDangerousTemplateIsTheLoudestSignal: a template that arrives already
// exploitable is the most alarming thing this epic can observe.
func TestNewDangerousTemplateIsTheLoudestSignal(t *testing.T) {
	before := []adcs.Template{{Name: "Existing", EKUs: []string{"1.3.6.1.5.5.7.3.1"}}}
	after := append(append([]adcs.Template(nil), before...), adcs.Template{
		Name: "BrandNew", SchemaVersion: 4, EnrolleeSuppliesSubject: true,
		EKUs: []string{adcs.EKUClientAuth}, PublishedBy: []string{"CORP-CA"},
		EnrollmentPrincipals: []string{"S-1-5-11"},
	})
	drift := adcs.DiffTemplates(before, after)
	if !drift.Worsened() {
		t.Fatal("a newly added exploitable template did not alert")
	}
	found := false
	for _, life := range drift.Lifecycle {
		if life.Template == "BrandNew" && life.Lifecycle == adcs.TemplateAdded && life.NowDangerous {
			found = true
		}
	}
	if !found {
		t.Fatalf("the new template was not reported as added-and-dangerous: %+v", drift.Lifecycle)
	}

	// Removing a dangerous template is recorded, and says it was dangerous, so
	// an incident timeline can tell "deleted an unused template" from "removed
	// the escalation path we reported".
	gone := adcs.DiffTemplates(after, before)
	for _, life := range gone.Lifecycle {
		if life.Template == "BrandNew" && life.Lifecycle == adcs.TemplateRemoved && !life.WasDangerous {
			t.Error("a removed dangerous template was not recorded as having been dangerous")
		}
	}
}
