// SPDX-License-Identifier: MPL-2.0

package adcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
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
)

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
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
	RequiredAgentRole  string `json:"required_agent_role"`
	RequiredAgentID    string `json:"required_agent_id,omitempty"`
}

type sourceConfig struct {
	URL                string `json:"url"`
	ConfigurationDN    string `json:"configuration_dn"`
	BindDN             string `json:"bind_dn"`
	PasswordRef        string `json:"password_ref"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
	RelayAgentID       string `json:"relay_agent_id,omitempty"`
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
	return InventoryIntent{
		JobKind: JobKind, Execution: ExecutionRelay, URL: directoryURL, ConfigurationDN: configurationDN,
		BindDN: bindDN, PasswordRef: passwordRef, InsecureSkipVerify: cfg.InsecureSkipVerify,
		RequiredAgentRole: RequiredRoleNetwork, RequiredAgentID: relayAgentID,
	}, nil
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
	if len(report.Findings) > MaxTemplates*8 {
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
	RunID             string     `json:"run_id"`
	SourceID          string     `json:"source_id"`
	Domain            string     `json:"domain"`
	AgentID           string     `json:"agent_id"`
	AgentName         string     `json:"agent_name"`
	DirectoryVerified bool       `json:"directory_verified"`
	Templates         []Template `json:"templates"`
	Findings          []Finding  `json:"findings"`
}
