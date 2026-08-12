// SPDX-License-Identifier: MPL-2.0

// Package adcs inventories an Active Directory Certificate Services deployment's
// certificate templates and enrollment services over LDAP (epic F1).
//
// A Windows PKI's real attack surface is not its CA — it is the template list.
// A template that lets the enrollee supply their own subject, grants enrollment
// to a broad group, and carries a client-authentication EKU is a domain
// escalation path that looks, in every console the organization owns, like an
// ordinary certificate template. Nobody has an inventory of these because the
// information lives in the directory rather than anywhere a PKI product looked.
//
// This reads it. Every attribute captured is one that changes whether a template
// is dangerous, and the dangerous combinations are named rather than left for an
// operator to spot across four columns.
//
// READ-ONLY, structurally. The package performs LDAP Search operations and
// nothing else — there is no Add, Modify, Delete, or ModifyDN call in it, and a
// test asserts that by inspecting the connection interface it depends on. That
// interface is deliberately narrow for exactly this reason: an inventory tool
// pointed at a domain controller must not be able to change one, even by bug.
package adcs

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Well-known AD CS container and object classes.
const (
	// PublicKeyServicesDN is the container, relative to the forest
	// configuration naming context, that holds templates and enrollment
	// services.
	PublicKeyServicesRDN = "CN=Public Key Services,CN=Services"
	// ClassCertificateTemplate is the object class of a certificate template.
	ClassCertificateTemplate = "pKICertificateTemplate"
	// ClassEnrollmentService is the object class of a published CA.
	ClassEnrollmentService = "pKIEnrollmentService"
)

// msPKI-Certificate-Name-Flag bits that matter for safety. There are more; these
// are the ones that decide whether a template can be used to impersonate.
const (
	// NameFlagEnrolleeSuppliesSubject lets the requester choose the subject.
	// Combined with a client-auth EKU and broad enrollment rights, this is the
	// canonical AD CS escalation: request a certificate naming a domain admin.
	NameFlagEnrolleeSuppliesSubject = 0x00000001
	// NameFlagEnrolleeSuppliesSubjectAltName lets the requester choose the SAN,
	// which is what modern clients actually authenticate on.
	NameFlagEnrolleeSuppliesSubjectAltName = 0x00010000
)

// msPKI-Enrollment-Flag bits that matter.
const (
	// EnrollmentFlagPendManagerApproval requires a human to approve each
	// issuance. Its ABSENCE is what makes an enrollee-supplies-subject template
	// immediately exploitable rather than merely alarming.
	EnrollmentFlagPendManagerApproval = 0x00000002
)

// msPKI-Private-Key-Flag bits that matter.
const (
	// PrivateKeyFlagExportableKey allows the private key to be exported. A
	// certificate whose key can be copied off the machine is one whose identity
	// can be, too.
	PrivateKeyFlagExportableKey = 0x00000010
)

// Client-authentication EKUs. A template that can impersonate is one that can be
// used to authenticate AS someone.
const (
	EKUClientAuth       = "1.3.6.1.5.5.7.3.2"
	EKUSmartcardLogon   = "1.3.6.1.4.1.311.20.2.2"
	EKUPKINITClientAuth = "1.3.6.1.5.2.3.4"
	EKUAnyPurpose       = "2.5.29.37.0"
	// EKUCertificateRequestAgent is the enrollment-agent EKU. A certificate
	// carrying it may request certificates ON BEHALF OF other principals, which
	// makes it a master key to every template that accepts enrollment-agent
	// requests — a distinct and worse primitive than impersonating one account.
	EKUCertificateRequestAgent = "1.3.6.1.4.1.311.20.2.1"
)

// Entry is one LDAP object as this package needs it: a DN and its attributes.
// Declaring it here rather than importing the LDAP library's type keeps the
// analysis testable without a directory, and keeps the wire library at one
// well-defined edge.
type Entry struct {
	DN               string
	Attributes       map[string][]string
	BinaryAttributes map[string][][]byte
}

// SearchRequest is one bounded, read-only LDAP query. DACLOnly asks the wire
// adapter to attach LDAP_SERVER_SD_FLAGS_OID with DACL_SECURITY_INFORMATION;
// keeping that request explicit is what lets tests prove the directory reader
// neither pulls SACLs nor relies on a server default.
type SearchRequest struct {
	BaseDN     string
	Filter     string
	Attributes []string
	MaxEntries int
	DACLOnly   bool
}

// Searcher is the narrow LDAP surface this package depends on.
//
// One method, and it reads. There is deliberately no Modify, Add, Delete or
// ModifyDN here: an inventory tool pointed at a domain controller must be
// structurally incapable of changing one, not merely careful not to. A test
// asserts this interface has exactly one method for that reason.
type Searcher interface {
	Search(ctx context.Context, request SearchRequest) ([]Entry, error)
}

// Template is one certificate template and the facts that decide whether it is
// dangerous.
type Template struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	OID         string `json:"oid,omitempty"`
	// SchemaVersion 1 templates cannot express many of the modern controls at
	// all — they have no enrollment flags an admin can tighten — so a v1
	// template with a client-auth EKU is a different conversation from a v4 one.
	SchemaVersion int `json:"schema_version,omitempty"`
	// EnrolleeSuppliesSubject and EnrolleeSuppliesSAN are the two flags that
	// turn a template into an impersonation primitive.
	EnrolleeSuppliesSubject bool `json:"enrollee_supplies_subject"`
	EnrolleeSuppliesSAN     bool `json:"enrollee_supplies_san"`
	// RequiresManagerApproval is the control that makes the above survivable.
	RequiresManagerApproval bool `json:"requires_manager_approval"`
	// ExportableKey means the private key can leave the machine it was issued to.
	ExportableKey bool `json:"exportable_key"`
	// EKUs are the extended key usages, by OID.
	EKUs []string `json:"ekus,omitempty"`
	// EnrollmentPrincipals are the security principals granted enrollment
	// rights, as the directory reports them. Who can use a dangerous template
	// is most of how dangerous it is.
	EnrollmentPrincipals []string `json:"enrollment_principals,omitempty"`
	// PublishedBy names the enrollment services (CAs) that offer this template.
	// A dangerous template nobody publishes is a latent risk; one published by
	// an issuing CA is a live one.
	PublishedBy []string `json:"published_by,omitempty"`
}

// AllowsClientAuthentication reports whether this template can produce a
// certificate usable to authenticate as someone.
func (t Template) AllowsClientAuthentication() bool {
	for _, eku := range t.EKUs {
		switch eku {
		case EKUClientAuth, EKUSmartcardLogon, EKUPKINITClientAuth, EKUAnyPurpose:
			return true
		}
	}
	// A template with NO EKUs is unrestricted, which is the same thing as any
	// purpose. Treating an empty list as harmless is a mistake worth not making.
	return len(t.EKUs) == 0
}

// EnrollmentService is one published CA.
type EnrollmentService struct {
	Name      string   `json:"name"`
	DNSName   string   `json:"dns_name,omitempty"`
	Templates []string `json:"templates,omitempty"`
	// EnrollmentWebServices are the CES URIs published in the directory's
	// msPKI-Enrollment-Servers attribute. They are not legacy /certsrv or NDES
	// endpoints; keeping the three concepts separate prevents a CES record from
	// being mislabelled as evidence that those IIS role services are absent.
	EnrollmentWebServices []string `json:"enrollment_web_services,omitempty"`
	// Endpoints are live, configured relay probes for IIS enrollment surfaces.
	// Only normalized URL/status/authentication facts cross the agent boundary;
	// response bodies and cookies are never retained.
	Endpoints []EnrollmentEndpoint `json:"endpoints,omitempty"`
	// AgentRestrictions is CA-side policy evidence. Template LDAP cannot answer
	// it. A collector that cannot read the CA policy reports unobserved rather
	// than turning missing evidence into an unsafe or safe guess.
	AgentRestrictions EnrollmentAgentRestrictions `json:"agent_restrictions"`
}

// EnrollmentEndpointKind is a closed IIS enrollment surface vocabulary.
type EnrollmentEndpointKind string

const (
	EndpointWebEnrollment EnrollmentEndpointKind = "web_enrollment"
	EndpointNDES          EnrollmentEndpointKind = "ndes"
	EndpointNDESAdmin     EnrollmentEndpointKind = "ndes_admin"
)

// EnrollmentEndpointState says what one bounded, no-body relay probe observed.
type EnrollmentEndpointState string

const (
	EndpointAnonymousAccess      EnrollmentEndpointState = "anonymous_access"
	EndpointAuthenticationNeeded EnrollmentEndpointState = "authentication_required"
	EndpointRedirected           EnrollmentEndpointState = "redirected"
	EndpointNotFound             EnrollmentEndpointState = "not_found"
	EndpointUnreachable          EnrollmentEndpointState = "unreachable"
	EndpointReachableOther       EnrollmentEndpointState = "reachable_other"
)

// EvidenceState is used for controls that require host/CA-side inspection.
type EvidenceState string

const (
	EvidenceEnabled    EvidenceState = "enabled"
	EvidenceDisabled   EvidenceState = "disabled"
	EvidenceUnobserved EvidenceState = "unobserved"
)

// EnrollmentEndpoint is one normalized live enrollment-service observation.
type EnrollmentEndpoint struct {
	Kind               EnrollmentEndpointKind  `json:"kind"`
	URL                string                  `json:"url"`
	State              EnrollmentEndpointState `json:"state"`
	HTTPStatus         int                     `json:"http_status,omitempty"`
	Authentication     []string                `json:"authentication,omitempty"`
	TLSVerified        bool                    `json:"tls_verified"`
	ExtendedProtection EvidenceState           `json:"extended_protection"`
}

// EnrollmentAgentRestrictions is the normalized CA policy result. Source is a
// non-secret collector label, never raw certutil/registry/RPC output.
type EnrollmentAgentRestrictions struct {
	State  EvidenceState `json:"state"`
	Source string        `json:"source"`
}

// Inventory is one domain's AD CS posture.
type Inventory struct {
	Templates          []Template          `json:"templates"`
	EnrollmentServices []EnrollmentService `json:"enrollment_services"`
}

// templateAttributes are the attributes read for each template. It is an
// explicit list rather than a wildcard so the query returns what the analysis
// uses and nothing else — an inventory tool should not be pulling attributes it
// has no reason to hold.
var templateAttributes = []string{
	"cn",
	"displayName",
	"msPKI-Cert-Template-OID",
	"msPKI-Template-Schema-Version",
	"msPKI-Certificate-Name-Flag",
	"msPKI-Enrollment-Flag",
	"msPKI-Private-Key-Flag",
	"pKIExtendedKeyUsage",
	"nTSecurityDescriptor",
}

var enrollmentServiceAttributes = []string{
	"cn",
	"dNSHostName",
	"certificateTemplates",
	"msPKI-Enrollment-Servers",
}

// Collect reads the templates and enrollment services under the given
// configuration naming context.
//
// configurationDN is the forest's configuration naming context (for example
// "CN=Configuration,DC=corp,DC=example"). The Public Key Services container is
// resolved relative to it rather than guessed from a domain name, because a
// forest root and a domain are not the same thing and guessing gets it wrong in
// exactly the multi-domain estates this matters most in.
func Collect(ctx context.Context, s Searcher, configurationDN string) (Inventory, error) {
	if s == nil {
		return Inventory{}, errors.New("adcs: no directory searcher")
	}
	if strings.TrimSpace(configurationDN) == "" {
		return Inventory{}, errors.New("adcs: the forest configuration naming context is required")
	}
	base := PublicKeyServicesRDN + "," + strings.TrimSpace(configurationDN)

	templateEntries, err := s.Search(ctx, SearchRequest{
		BaseDN:     "CN=Certificate Templates," + base,
		Filter:     "(objectClass=" + ClassCertificateTemplate + ")",
		Attributes: append([]string(nil), templateAttributes...),
		MaxEntries: MaxTemplates, DACLOnly: true,
	})
	if err != nil {
		return Inventory{}, fmt.Errorf("adcs: read certificate templates: %w", err)
	}
	serviceEntries, err := s.Search(ctx, SearchRequest{
		BaseDN:     "CN=Enrollment Services," + base,
		Filter:     "(objectClass=" + ClassEnrollmentService + ")",
		Attributes: append([]string(nil), enrollmentServiceAttributes...),
		MaxEntries: MaxEnrollmentServices,
	})
	if err != nil {
		return Inventory{}, fmt.Errorf("adcs: read enrollment services: %w", err)
	}

	inventory := Inventory{}
	publishedBy := map[string][]string{}
	for _, entry := range serviceEntries {
		service := EnrollmentService{
			Name:                  first(entry.Attributes["cn"]),
			DNSName:               first(entry.Attributes["dNSHostName"]),
			Templates:             append([]string(nil), entry.Attributes["certificateTemplates"]...),
			EnrollmentWebServices: enrollmentWebServiceURLs(entry.Attributes["msPKI-Enrollment-Servers"]),
			AgentRestrictions:     EnrollmentAgentRestrictions{State: EvidenceUnobserved, Source: "ca_policy_not_observed"},
		}
		sort.Strings(service.Templates)
		for _, name := range service.Templates {
			publishedBy[name] = append(publishedBy[name], service.Name)
		}
		inventory.EnrollmentServices = append(inventory.EnrollmentServices, service)
	}
	sort.Slice(inventory.EnrollmentServices, func(i, j int) bool {
		return inventory.EnrollmentServices[i].Name < inventory.EnrollmentServices[j].Name
	})

	for _, entry := range templateEntries {
		t, err := templateFromEntry(entry)
		if err != nil {
			return Inventory{}, fmt.Errorf("adcs: decode certificate template %q: %w", entry.DN, err)
		}
		if names := publishedBy[t.Name]; len(names) > 0 {
			sort.Strings(names)
			t.PublishedBy = names
		}
		inventory.Templates = append(inventory.Templates, t)
	}
	sort.Slice(inventory.Templates, func(i, j int) bool {
		return inventory.Templates[i].Name < inventory.Templates[j].Name
	})
	return inventory, nil
}

// enrollmentWebServiceURLs extracts only absolute HTTP(S) URIs from the
// multi-line msPKI-Enrollment-Servers values. Microsoft encodes priority and
// authentication metadata beside the URI; those fields are not guessed into
// security controls here. The URI is the stable fact this LDAP attribute owns.
func enrollmentWebServiceURLs(values []string) []string {
	seen := make(map[string]bool)
	for _, value := range values {
		for _, line := range strings.FieldsFunc(value, func(r rune) bool { return r == '\r' || r == '\n' }) {
			candidate := strings.TrimSpace(line)
			parsed, err := url.Parse(candidate)
			if err == nil && parsed.Hostname() != "" && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.User == nil {
				seen[parsed.String()] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// templateFromEntry decodes one template object.
func templateFromEntry(entry Entry) (Template, error) {
	nameFlag := intAttr(entry.Attributes["msPKI-Certificate-Name-Flag"])
	enrollFlag := intAttr(entry.Attributes["msPKI-Enrollment-Flag"])
	keyFlag := intAttr(entry.Attributes["msPKI-Private-Key-Flag"])
	ekus := append([]string(nil), entry.Attributes["pKIExtendedKeyUsage"]...)
	sort.Strings(ekus)
	descriptors := entry.BinaryAttributes["nTSecurityDescriptor"]
	if len(descriptors) != 1 {
		return Template{}, errors.New("directory returned no single nTSecurityDescriptor")
	}
	principals, err := EnrollmentPrincipalsFromSecurityDescriptor(descriptors[0])
	if err != nil {
		return Template{}, err
	}
	return Template{
		Name:                    first(entry.Attributes["cn"]),
		DisplayName:             first(entry.Attributes["displayName"]),
		OID:                     first(entry.Attributes["msPKI-Cert-Template-OID"]),
		SchemaVersion:           intAttr(entry.Attributes["msPKI-Template-Schema-Version"]),
		EnrolleeSuppliesSubject: nameFlag&NameFlagEnrolleeSuppliesSubject != 0,
		EnrolleeSuppliesSAN:     nameFlag&NameFlagEnrolleeSuppliesSubjectAltName != 0,
		RequiresManagerApproval: enrollFlag&EnrollmentFlagPendManagerApproval != 0,
		ExportableKey:           keyFlag&PrivateKeyFlagExportableKey != 0,
		EKUs:                    ekus,
		EnrollmentPrincipals:    principals,
	}, nil
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

// intAttr parses a numeric LDAP attribute. AD stores these flags as decimal
// strings; a value that does not parse is treated as zero, which is the safe
// direction — it under-claims a flag rather than inventing one.
func intAttr(values []string) int {
	v, err := strconv.Atoi(first(values))
	if err != nil {
		return 0
	}
	return v
}
