// SPDX-License-Identifier: MPL-2.0

package adcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

const (
	// SourceKind is the discovery-source kind operators configure.
	SourceKind = "adcs"
	// JobKind is the estate-owned outbox destination a network relay claims.
	JobKind             = "adcs.inventory"
	ExecutionRelay      = "relay"
	RequiredRoleNetwork = "network"
	maxIntentTextBytes  = 4_096
	maxPrincipals       = 1_024
	maxEndpointTargets  = 24
	maxPrivateCIDRs     = 16
	// InventoryEventSchemaVersion adds normalized enrollment-service evidence.
	// V1 remains replayable as template-only history.
	InventoryEventSchemaVersion = 2
)

// EnrollmentEndpointTarget is one operator-scoped IIS surface the in-domain
// relay may probe. The service name binds a network URL back to the exact LDAP
// enrollment-service object whose posture is being reported.
type EnrollmentEndpointTarget struct {
	EnrollmentService string                 `json:"enrollment_service"`
	Kind              EnrollmentEndpointKind `json:"kind"`
	URL               string                 `json:"url"`
}

// InventoryIntent is the reference-only relay command. The standard run fields
// bind the command to its generic lifecycle; the AD CS fields tell the relay
// what to read. Connection fields stay in the outbox command and are not copied
// into the immutable discovery.run.queued event.
type InventoryIntent struct {
	ID              string  `json:"id"`
	SourceID        string  `json:"source_id"`
	JobKind         string  `json:"job_kind"`
	ScheduleID      *string `json:"schedule_id,omitempty"`
	DryRun          bool    `json:"dry_run"`
	RequestedBy     string  `json:"requested_by,omitempty"`
	Execution       string  `json:"execution"`
	URL             string  `json:"url"`
	ConfigurationDN string  `json:"configuration_dn"`
	BindDN          string  `json:"bind_dn"`
	PasswordRef     string  `json:"password_ref"`
	// InsecureSkipVerify is a lab-only escape hatch and remains visible in the
	// command/report so unverified directory identity cannot masquerade as
	// verified evidence.
	InsecureSkipVerify   bool                       `json:"insecure_skip_verify,omitempty"`
	RequiredAgentRole    string                     `json:"required_agent_role"`
	RequiredAgentID      string                     `json:"required_agent_id,omitempty"`
	EnrollmentEndpoints  []EnrollmentEndpointTarget `json:"enrollment_endpoints,omitempty"`
	AllowPrivateEndpoint bool                       `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string                   `json:"private_egress_cidrs,omitempty"`
}

type sourceConfig struct {
	URL                  string                     `json:"url"`
	ConfigurationDN      string                     `json:"configuration_dn"`
	BindDN               string                     `json:"bind_dn"`
	PasswordRef          string                     `json:"password_ref"`
	InsecureSkipVerify   bool                       `json:"insecure_skip_verify,omitempty"`
	RelayAgentID         string                     `json:"relay_agent_id,omitempty"`
	EnrollmentEndpoints  []EnrollmentEndpointTarget `json:"enrollment_endpoints,omitempty"`
	AllowPrivateEndpoint bool                       `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string                   `json:"private_egress_cidrs,omitempty"`
}

// ResolveInventoryIntent validates operator configuration and produces the
// exact relay command. Unknown fields fail closed so a misspelled credential
// reference or TLS option cannot be accepted and then ignored.
func ResolveInventoryIntent(raw json.RawMessage) (InventoryIntent, error) {
	var cfg sourceConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return InventoryIntent{}, fmt.Errorf("adcs: decode source config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return InventoryIntent{}, errors.New("adcs: source config has trailing JSON")
	}
	directoryURL := strings.TrimSpace(cfg.URL)
	parsed, err := url.Parse(directoryURL)
	if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "ldap" && parsed.Scheme != "ldaps") ||
		parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return InventoryIntent{}, errors.New("adcs: url must be an ldap:// or ldaps:// directory authority without credentials, path, query, or fragment")
	}
	if parsed.Port() != "" {
		if port, parseErr := strconv.Atoi(parsed.Port()); parseErr != nil || port < 1 || port > 65535 {
			return InventoryIntent{}, errors.New("adcs: url has an invalid port")
		}
	}
	configurationDN := strings.TrimSpace(cfg.ConfigurationDN)
	bindDN := strings.TrimSpace(cfg.BindDN)
	passwordRef := strings.TrimSpace(cfg.PasswordRef)
	for name, value := range map[string]string{
		"url": directoryURL, "configuration_dn": configurationDN, "bind_dn": bindDN, "password_ref": passwordRef,
	} {
		if value == "" || len(value) > maxIntentTextBytes {
			return InventoryIntent{}, fmt.Errorf("adcs: %s is required and must be at most %d bytes", name, maxIntentTextBytes)
		}
	}
	if !strings.HasPrefix(passwordRef, "secret://") || strings.TrimPrefix(passwordRef, "secret://") == "" {
		return InventoryIntent{}, errors.New("adcs: password_ref must be a secret:// credential reference")
	}
	relayAgentID := strings.TrimSpace(cfg.RelayAgentID)
	if relayAgentID != "" {
		if _, err := uuid.Parse(relayAgentID); err != nil {
			return InventoryIntent{}, errors.New("adcs: relay_agent_id must be a UUID")
		}
	}
	endpoints, err := normalizeEnrollmentEndpointTargets(cfg.EnrollmentEndpoints)
	if err != nil {
		return InventoryIntent{}, err
	}
	privateCIDRs, err := normalizePrivateEgressCIDRs(cfg.AllowPrivateEndpoint, cfg.PrivateEgressCIDRs, len(endpoints) > 0)
	if err != nil {
		return InventoryIntent{}, err
	}
	return InventoryIntent{
		JobKind: JobKind, Execution: ExecutionRelay, URL: directoryURL, ConfigurationDN: configurationDN,
		BindDN: bindDN, PasswordRef: passwordRef, InsecureSkipVerify: cfg.InsecureSkipVerify,
		RequiredAgentRole: RequiredRoleNetwork, RequiredAgentID: relayAgentID,
		EnrollmentEndpoints:  endpoints,
		AllowPrivateEndpoint: cfg.AllowPrivateEndpoint, PrivateEgressCIDRs: privateCIDRs,
	}, nil
}

var adcsPrivateNetworks = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

func normalizePrivateEgressCIDRs(allow bool, raw []string, hasEndpoints bool) ([]string, error) {
	if len(raw) > maxPrivateCIDRs {
		return nil, fmt.Errorf("adcs: private_egress_cidrs exceeds %d entries", maxPrivateCIDRs)
	}
	if !allow && len(raw) != 0 {
		return nil, errors.New("adcs: private_egress_cidrs requires allow_private_endpoint")
	}
	if allow && (!hasEndpoints || len(raw) == 0) {
		return nil, errors.New("adcs: private endpoint egress requires configured enrollment endpoints and private_egress_cidrs")
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, value := range raw {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("adcs: private_egress_cidrs contains invalid CIDR %q", value)
		}
		prefix = prefix.Masked()
		insidePrivateNetwork := false
		for _, privateNetwork := range adcsPrivateNetworks {
			if privateNetwork.Addr().BitLen() == prefix.Addr().BitLen() &&
				prefix.Bits() >= privateNetwork.Bits() && privateNetwork.Contains(prefix.Addr()) {
				insidePrivateNetwork = true
				break
			}
		}
		if !insidePrivateNetwork {
			return nil, fmt.Errorf("adcs: private_egress_cidrs %q is not inside RFC1918 or IPv6 ULA space", value)
		}
		canonical := prefix.String()
		if seen[canonical] {
			return nil, fmt.Errorf("adcs: private_egress_cidrs duplicates %q", canonical)
		}
		seen[canonical] = true
		out = append(out, canonical)
	}
	sort.Strings(out)
	return out, nil
}

// PrivateEgressPrefixes revalidates the command's explicit private-network
// allowance at the relay boundary. The outbox payload is signed, but treating
// it as already normalized would make a future producer bug an SSRF bypass.
func (i InventoryIntent) PrivateEgressPrefixes() ([]netip.Prefix, error) {
	normalized, err := normalizePrivateEgressCIDRs(i.AllowPrivateEndpoint, i.PrivateEgressCIDRs, len(i.EnrollmentEndpoints) > 0)
	if err != nil {
		return nil, err
	}
	prefixes := make([]netip.Prefix, 0, len(normalized))
	for _, raw := range normalized {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("adcs: parse normalized private egress CIDR: %w", err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func normalizeEnrollmentEndpointTargets(targets []EnrollmentEndpointTarget) ([]EnrollmentEndpointTarget, error) {
	if len(targets) > maxEndpointTargets {
		return nil, fmt.Errorf("adcs: enrollment endpoint count exceeds %d", maxEndpointTargets)
	}
	out := make([]EnrollmentEndpointTarget, 0, len(targets))
	seen := make(map[string]bool, len(targets))
	for i, target := range targets {
		target.EnrollmentService = strings.TrimSpace(target.EnrollmentService)
		target.URL = strings.TrimSpace(target.URL)
		if err := boundedReportText("enrollment service", target.EnrollmentService); err != nil {
			return nil, fmt.Errorf("adcs: enrollment endpoint %d: %w", i, err)
		}
		switch target.Kind {
		case EndpointWebEnrollment, EndpointNDES, EndpointNDESAdmin:
		default:
			return nil, fmt.Errorf("adcs: enrollment endpoint %d has an unknown kind", i)
		}
		parsed, err := url.Parse(target.URL)
		if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
			parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("adcs: enrollment endpoint %d must be an absolute HTTP(S) URL without credentials, query, or fragment", i)
		}
		if parsed.Port() != "" {
			port, parseErr := strconv.Atoi(parsed.Port())
			if parseErr != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("adcs: enrollment endpoint %d has an invalid port", i)
			}
		}
		key := target.EnrollmentService + "\x00" + string(target.Kind) + "\x00" + target.URL
		if seen[key] {
			return nil, fmt.Errorf("adcs: enrollment endpoint %d is duplicated", i)
		}
		seen[key] = true
		out = append(out, target)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EnrollmentService != out[j].EnrollmentService {
			return out[i].EnrollmentService < out[j].EnrollmentService
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].URL < out[j].URL
	})
	return out, nil
}

// InventoryReport is the bounded semantic result covered by an agent receipt.
// Status is the discovery run outcome, not the transport outcome: a relay can
// execute a read attempt and truthfully report that the directory read failed.
type InventoryReport struct {
	Status            string    `json:"status"`
	ErrorCode         string    `json:"error_code,omitempty"`
	Inventory         Inventory `json:"inventory"`
	Findings          []Finding `json:"findings"`
	DirectoryVerified bool      `json:"directory_verified"`
}

var inventoryFailureCodes = map[string]bool{
	"directory_unreachable":           true,
	"directory_tls_failed":            true,
	"directory_authentication_failed": true,
	"directory_read_failed":           true,
	"inventory_empty":                 true,
}

// ValidateInventoryReport binds normalized relay output to a valid command and
// enforces report bounds before any immutable event or read model changes.
func ValidateInventoryReport(intent InventoryIntent, report InventoryReport) error {
	if intent.ID == "" || intent.SourceID == "" || intent.JobKind != JobKind || intent.Execution != ExecutionRelay ||
		intent.RequiredAgentRole != RequiredRoleNetwork {
		return errors.New("adcs: command is not a relay-owned discovery run")
	}
	switch report.Status {
	case "failed":
		if !inventoryFailureCodes[report.ErrorCode] {
			return errors.New("adcs: failed report has an unknown closed error code")
		}
		if len(report.Inventory.Templates) != 0 || len(report.Inventory.EnrollmentServices) != 0 || len(report.Findings) != 0 {
			return errors.New("adcs: failed report carries invented inventory")
		}
		return nil
	case "succeeded":
		if report.ErrorCode != "" {
			return errors.New("adcs: succeeded report carries an error code")
		}
	default:
		return errors.New("adcs: report status must be succeeded or failed")
	}
	if len(report.Inventory.Templates) == 0 || len(report.Inventory.Templates) > MaxTemplates {
		return errors.New("adcs: succeeded report must carry a bounded non-empty template inventory")
	}
	if len(report.Inventory.EnrollmentServices) > MaxEnrollmentServices {
		return errors.New("adcs: enrollment-service count exceeds the report bound")
	}
	if len(report.Findings) > MaxTemplates*8+MaxEnrollmentServices*16 {
		return errors.New("adcs: finding count exceeds the report bound")
	}
	seen := make(map[string]struct{}, len(report.Inventory.Templates))
	for i, template := range report.Inventory.Templates {
		if err := boundedReportText("template name", template.Name); err != nil {
			return fmt.Errorf("adcs: template %d: %w", i, err)
		}
		if _, duplicate := seen[template.Name]; duplicate {
			return fmt.Errorf("adcs: template %d duplicates %q", i, template.Name)
		}
		seen[template.Name] = struct{}{}
		if len(template.EnrollmentPrincipals) > maxPrincipals {
			return fmt.Errorf("adcs: template %d enrollment-principal count exceeds the report bound", i)
		}
		previous := ""
		for _, principal := range template.EnrollmentPrincipals {
			if err := validateCanonicalSIDText(principal); err != nil {
				return fmt.Errorf("adcs: template %d enrollment principal: %w", i, err)
			}
			if principal <= previous {
				return fmt.Errorf("adcs: template %d enrollment principals are not unique and sorted", i)
			}
			previous = principal
		}
	}
	if err := validateEnrollmentServices(intent, report.Inventory.EnrollmentServices); err != nil {
		return err
	}
	want, err := json.Marshal(Findings(report.Inventory))
	if err != nil {
		return fmt.Errorf("adcs: encode recomputed findings: %w", err)
	}
	got, err := json.Marshal(report.Findings)
	if err != nil {
		return fmt.Errorf("adcs: encode reported findings: %w", err)
	}
	if !bytes.Equal(got, want) {
		return errors.New("adcs: reported findings do not exactly match the normalized inventory")
	}
	return nil
}

func validateEnrollmentServices(intent InventoryIntent, services []EnrollmentService) error {
	seenServices := make(map[string]bool, len(services))
	targets, err := normalizeEnrollmentEndpointTargets(intent.EnrollmentEndpoints)
	if err != nil {
		return err
	}
	wantTargets := make(map[string]EnrollmentEndpointTarget, len(targets))
	for _, target := range targets {
		wantTargets[target.EnrollmentService+"\x00"+string(target.Kind)+"\x00"+target.URL] = target
	}
	seenTargets := make(map[string]bool, len(targets))
	for i, service := range services {
		if err := boundedReportText("enrollment service name", service.Name); err != nil {
			return fmt.Errorf("adcs: enrollment service %d: %w", i, err)
		}
		if seenServices[service.Name] {
			return fmt.Errorf("adcs: enrollment service %d duplicates %q", i, service.Name)
		}
		seenServices[service.Name] = true
		switch service.AgentRestrictions.State {
		case EvidenceEnabled, EvidenceDisabled, EvidenceUnobserved:
		default:
			return fmt.Errorf("adcs: enrollment service %d has an unknown agent-restriction state", i)
		}
		if err := boundedReportText("agent-restriction source", service.AgentRestrictions.Source); err != nil {
			return fmt.Errorf("adcs: enrollment service %d: %w", i, err)
		}
		previous := ""
		for j, endpoint := range service.Endpoints {
			key := service.Name + "\x00" + string(endpoint.Kind) + "\x00" + endpoint.URL
			if _, configured := wantTargets[key]; !configured {
				return fmt.Errorf("adcs: enrollment service %d endpoint %d was not configured by the command", i, j)
			}
			if seenTargets[key] || (previous != "" && key <= previous) {
				return fmt.Errorf("adcs: enrollment service %d endpoints are duplicated or unsorted", i)
			}
			seenTargets[key] = true
			previous = key
			switch endpoint.State {
			case EndpointAnonymousAccess, EndpointAuthenticationNeeded, EndpointRedirected, EndpointNotFound, EndpointUnreachable, EndpointReachableOther:
			default:
				return fmt.Errorf("adcs: enrollment service %d endpoint %d has an unknown state", i, j)
			}
			if endpoint.ExtendedProtection != EvidenceEnabled && endpoint.ExtendedProtection != EvidenceDisabled && endpoint.ExtendedProtection != EvidenceUnobserved {
				return fmt.Errorf("adcs: enrollment service %d endpoint %d has an unknown extended-protection state", i, j)
			}
		}
	}
	if len(seenTargets) != len(wantTargets) {
		return errors.New("adcs: report omitted one or more configured enrollment endpoints")
	}
	return nil
}

func boundedReportText(name, value string) error {
	if strings.TrimSpace(value) == "" || len(value) > maxIntentTextBytes {
		return fmt.Errorf("%s is empty or exceeds %d bytes", name, maxIntentTextBytes)
	}
	return nil
}

func validateCanonicalSIDText(value string) error {
	parts := strings.Split(value, "-")
	if len(parts) < 3 || parts[0] != "S" || parts[1] != "1" || len(parts)-3 > 15 {
		return errors.New("SID is not canonical S-1-authority-subauthority text")
	}
	authority, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil || strconv.FormatUint(authority, 10) != parts[2] {
		return errors.New("SID authority is not canonical")
	}
	for _, part := range parts[3:] {
		sub, err := strconv.ParseUint(part, 10, 32)
		if err != nil || strconv.FormatUint(sub, 10) != part {
			return errors.New("SID subauthority is not canonical")
		}
	}
	return nil
}

// InventoryObserved is the immutable normalized posture event. It deliberately
// has no bind credential and no raw descriptor field.
type InventoryObserved struct {
	RunID              string              `json:"run_id"`
	SourceID           string              `json:"source_id"`
	Domain             string              `json:"domain"`
	AgentID            string              `json:"agent_id"`
	AgentName          string              `json:"agent_name"`
	DirectoryVerified  bool                `json:"directory_verified"`
	Templates          []Template          `json:"templates"`
	EnrollmentServices []EnrollmentService `json:"enrollment_services"`
	Findings           []Finding           `json:"findings"`
}

// InventoryObservedV1 is the exact historical template-only event shape.
// Keeping it closed prevents adding a v2 field under the old privacy schema.
type InventoryObservedV1 struct {
	RunID             string     `json:"run_id"`
	SourceID          string     `json:"source_id"`
	Domain            string     `json:"domain"`
	AgentID           string     `json:"agent_id"`
	AgentName         string     `json:"agent_name"`
	DirectoryVerified bool       `json:"directory_verified"`
	Templates         []Template `json:"templates"`
	Findings          []Finding  `json:"findings"`
}
