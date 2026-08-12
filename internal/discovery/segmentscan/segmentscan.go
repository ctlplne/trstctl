// SPDX-License-Identifier: MPL-2.0

// Package segmentscan defines the bounded command and report exchanged between
// the control plane and a network-role relay for network and SSH discovery.
// It deliberately contains no transport or store code: both sides validate the
// same JSON shape without either side importing the other's process package.
package segmentscan

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/discovery/netscan"
)

const (
	ModeTLS = "tls"
	ModeSSH = "ssh"

	ExecutionRelay        = "relay"
	ExecutionControlPlane = "control_plane"
	RequiredRoleNetwork   = "network"
	MaxTargets            = 10_000
	maxFindings           = MaxTargets
	maxTextBytes          = 4_096
)

// Intent is the immutable discovery.run command. For relay-owned source kinds,
// the queued event and the outbox payload are the same bytes.
type Intent struct {
	ID       string `json:"id"`
	SourceID string `json:"source_id"`
	// JobKind is empty for historical/control-plane and ordinary segment-scan
	// events. Specialized relay commands set it so boot reconciliation restores
	// the same destination instead of guessing from mutable source state.
	JobKind       string   `json:"job_kind,omitempty"`
	ScheduleID    *string  `json:"schedule_id,omitempty"`
	DryRun        bool     `json:"dry_run"`
	RequestedBy   string   `json:"requested_by,omitempty"`
	Execution     string   `json:"execution,omitempty"`
	Mode          string   `json:"mode,omitempty"`
	Targets       []string `json:"targets,omitempty"`
	AllowRFC1918  bool     `json:"allow_rfc1918,omitempty"`
	AllowLoopback bool     `json:"allow_loopback,omitempty"`
	// AllowReservedRanges is a decode-only compatibility field for pre-C2 unit
	// fixtures. Live queue producers use the two explicit policy switches above.
	AllowReservedRanges bool   `json:"allow_reserved_ranges,omitempty"`
	Segment             string `json:"segment,omitempty"`
	RequiredAgentRole   string `json:"required_agent_role,omitempty"`
	RequiredAgentID     string `json:"required_agent_id,omitempty"`
}

type sourceConfig struct {
	Targets       []string `json:"targets"`
	CIDRs         []string `json:"cidrs"`
	CIDR          string   `json:"cidr"`
	Ports         []int    `json:"ports"`
	AllowRFC1918  bool     `json:"allow_rfc1918"`
	AllowLoopback bool     `json:"allow_loopback"`
	Segment       string   `json:"segment"`
	RelayAgentID  string   `json:"relay_agent_id"`
}

// Resolve converts source configuration into the exact bounded relay command.
func Resolve(kind string, raw json.RawMessage) (Intent, error) {
	mode := ""
	switch strings.TrimSpace(kind) {
	case "network":
		mode = ModeTLS
	case "ssh":
		mode = ModeSSH
	default:
		return Intent{}, fmt.Errorf("segment scan: source kind %q is not relay-owned", kind)
	}
	var cfg sourceConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Intent{}, fmt.Errorf("segment scan: decode %s source config: %w", kind, err)
	}
	segment := strings.TrimSpace(cfg.Segment)
	if segment == "" {
		return Intent{}, errors.New("segment scan: network and SSH discovery sources require a declared segment")
	}
	if err := boundedText("segment", segment); err != nil {
		return Intent{}, err
	}
	relayAgentID := strings.TrimSpace(cfg.RelayAgentID)
	if relayAgentID != "" {
		if _, err := uuid.Parse(relayAgentID); err != nil {
			return Intent{}, errors.New("segment scan: relay_agent_id must be a UUID")
		}
	}

	targets := make([]string, 0, len(cfg.Targets))
	for _, target := range cfg.Targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(target); err != nil {
			return Intent{}, fmt.Errorf("segment scan: target %q must be host:port", target)
		}
		targets = append(targets, target)
	}
	cidrs := append([]string(nil), cfg.CIDRs...)
	if strings.TrimSpace(cfg.CIDR) != "" {
		cidrs = append(cidrs, cfg.CIDR)
	}
	ports := append([]int(nil), cfg.Ports...)
	if mode == ModeSSH && len(cidrs) > 0 && len(ports) == 0 {
		ports = []int{22}
	}
	for _, cidr := range cidrs {
		expanded, err := netscan.ExpandRange(strings.TrimSpace(cidr), ports)
		if err != nil {
			return Intent{}, err
		}
		targets = append(targets, expanded...)
	}
	targets = stableUnique(targets)
	if len(targets) == 0 {
		if mode == ModeSSH {
			return Intent{}, errors.New("segment scan: SSH discovery source requires targets or cidrs")
		}
		return Intent{}, errors.New("segment scan: network discovery source requires targets or cidrs+ports")
	}
	if len(targets) > MaxTargets {
		return Intent{}, fmt.Errorf("segment scan: source has %d targets; maximum is %d", len(targets), MaxTargets)
	}
	return Intent{
		Execution: ExecutionRelay, Mode: mode, Targets: targets,
		AllowRFC1918: cfg.AllowRFC1918, AllowLoopback: cfg.AllowLoopback,
		Segment: segment, RequiredAgentRole: RequiredRoleNetwork, RequiredAgentID: relayAgentID,
	}, nil
}

// Finding is public credential metadata observed at one assigned target. No
// certificate bytes, SSH public-key bytes, credentials, or arbitrary relay text
// are accepted by this protocol.
type Finding struct {
	Address       string   `json:"address"`
	Fingerprint   string   `json:"fingerprint"`
	Subject       string   `json:"subject,omitempty"`
	Issuer        string   `json:"issuer,omitempty"`
	Serial        string   `json:"serial,omitempty"`
	KeyType       string   `json:"key_type,omitempty"`
	SANs          []string `json:"sans,omitempty"`
	NotBefore     string   `json:"not_before,omitempty"`
	NotAfter      string   `json:"not_after,omitempty"`
	PublicKeyBits int      `json:"public_key_bits,omitempty"`
	IsCA          bool     `json:"is_ca,omitempty"`
}

// Report is the relay's bounded observation result.
type Report struct {
	Mode       string    `json:"mode"`
	Findings   []Finding `json:"findings"`
	Targets    int       `json:"targets"`
	Discovered int       `json:"discovered"`
	Failed     int       `json:"failed"`
	Rejected   int       `json:"rejected"`
	Blocked    int       `json:"blocked"`
}

// ValidateReport binds a report to the exact assigned command before any event
// or read model is changed.
func ValidateReport(intent Intent, report Report) error {
	if intent.Execution != ExecutionRelay || intent.RequiredAgentRole != RequiredRoleNetwork {
		return errors.New("segment scan: command is not relay-owned network work")
	}
	if report.Mode != intent.Mode || (report.Mode != ModeTLS && report.Mode != ModeSSH) {
		return errors.New("segment scan: report mode does not match command")
	}
	if report.Targets != len(intent.Targets) {
		return errors.New("segment scan: report target count does not match command")
	}
	if report.Targets < 0 || report.Discovered < 0 || report.Failed < 0 || report.Rejected < 0 || report.Blocked < 0 {
		return errors.New("segment scan: report counts must not be negative")
	}
	if report.Discovered != len(report.Findings) || len(report.Findings) > maxFindings {
		return errors.New("segment scan: reported findings do not match discovered count")
	}
	if report.Discovered+report.Failed+report.Rejected+report.Blocked != report.Targets {
		return errors.New("segment scan: report outcome counts do not cover assigned targets")
	}
	if intent.DryRun && (len(report.Findings) != 0 || report.Failed != 0 || report.Rejected != 0 || report.Blocked != 0) {
		return errors.New("segment scan: dry run reported target effects")
	}
	assigned := make(map[string]struct{}, len(intent.Targets))
	for _, target := range intent.Targets {
		assigned[target] = struct{}{}
	}
	seen := make(map[string]struct{}, len(report.Findings))
	for i, finding := range report.Findings {
		if _, ok := assigned[finding.Address]; !ok {
			return fmt.Errorf("segment scan: finding %d names an unassigned target", i)
		}
		if strings.TrimSpace(finding.Fingerprint) == "" {
			return fmt.Errorf("segment scan: finding %d has no fingerprint", i)
		}
		for name, value := range map[string]string{
			"address": finding.Address, "fingerprint": finding.Fingerprint,
			"subject": finding.Subject, "issuer": finding.Issuer, "serial": finding.Serial,
			"key_type": finding.KeyType, "not_before": finding.NotBefore, "not_after": finding.NotAfter,
		} {
			if err := boundedText(name, value); err != nil {
				return fmt.Errorf("segment scan: finding %d: %w", i, err)
			}
		}
		if finding.PublicKeyBits < 0 || len(finding.SANs) > 256 {
			return fmt.Errorf("segment scan: finding %d has invalid public-key metadata", i)
		}
		for _, san := range finding.SANs {
			if err := boundedText("SAN", san); err != nil {
				return fmt.Errorf("segment scan: finding %d: %w", i, err)
			}
		}
		key := finding.Address + "\x00" + finding.Fingerprint
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("segment scan: finding %d duplicates an earlier observation", i)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func Status(report Report) (status, reason string) {
	if report.Failed+report.Rejected+report.Blocked == 0 {
		return "succeeded", ""
	}
	if report.Discovered > 0 {
		return "partial", "some relay discovery probes failed or were blocked"
	}
	return "failed", "all relay discovery probes failed or were blocked"
}

func stableUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func boundedText(name, value string) error {
	if !utf8.ValidString(value) || len(value) > maxTextBytes {
		return fmt.Errorf("%s exceeds the metadata bound", name)
	}
	return nil
}
