// SPDX-License-Identifier: BUSL-1.1

// Package sshcollection is the reference-only, read-only agentless SSH contract.
package sshcollection

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"trstctl.com/trstctl/internal/crypto"
)

const SourceKind = "ssh_trust"
const Destination = "ssh.trust.collect"
const RemoteCommand = crypto.SSHCollectionCommand
const MaxHosts = 100
const MaxReportBytes = 2 << 20
const MaxCommandBytes = 256 << 10

var usernameRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// Host contains public routing, a host identity pin and a vault reference.
// The command and readable paths are fixed by a root-owned remote helper.
type Host struct {
	Address            string `json:"address"`
	Username           string `json:"username"`
	HostKeyFingerprint string `json:"host_key_fingerprint"`
	CredentialRef      string `json:"credential_ref"`
}

type Config struct {
	Enabled       bool   `json:"enabled"`
	Segment       string `json:"segment"`
	RelayAgentID  string `json:"relay_agent_id"`
	AllowRFC1918  bool   `json:"allow_rfc1918,omitempty"`
	AllowLoopback bool   `json:"allow_loopback,omitempty"`
	Hosts         []Host `json:"hosts"`
}

// Command is the immutable source command. It carries no credential value or
// caller-selected command. A network relay redeems its references for one job.
type Command struct {
	ID                string  `json:"id"`
	SourceID          string  `json:"source_id"`
	JobKind           string  `json:"job_kind"`
	ScheduleID        *string `json:"schedule_id,omitempty"`
	RetryOfRunID      string  `json:"retry_of_run_id,omitempty"`
	RequestedBy       string  `json:"requested_by,omitempty"`
	Execution         string  `json:"execution"`
	RequiredAgentRole string  `json:"required_agent_role"`
	RequiredAgentID   string  `json:"required_agent_id"`
	Segment           string  `json:"segment"`
	AllowRFC1918      bool    `json:"allow_rfc1918,omitempty"`
	AllowLoopback     bool    `json:"allow_loopback,omitempty"`
	Hosts             []Host  `json:"hosts"`
}

func DecodeConfig(raw []byte) (Config, error) {
	var c Config
	if err := decode(raw, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}
func DecodeCommand(raw []byte) (Command, error) {
	var c Command
	if err := decode(raw, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}
func decode(raw []byte, out any) error {
	return decodeBounded(raw, out, MaxCommandBytes)
}
func decodeBounded(raw []byte, out any, limit int) error {
	if len(raw) == 0 || len(raw) > limit {
		return errors.New("SSH collection input exceeds its bound")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("SSH collection input has trailing JSON")
	}
	return nil
}
func canonicalID(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}
func (c Config) Validate() error {
	if !c.Enabled {
		return errors.New("agentless SSH trust collection needs explicit enabled=true")
	}
	if !canonicalID(c.RelayAgentID) {
		return errors.New("select one enrolled tenant network relay")
	}
	return validateScope(c.Segment, c.Hosts)
}
func validateScope(segment string, hosts []Host) error {
	if segment == "" || strings.TrimSpace(segment) != segment || len(segment) > 128 || strings.ContainsAny(segment, "\x00\r\n") {
		return errors.New("declare one bounded discovery segment")
	}
	if len(hosts) == 0 || len(hosts) > MaxHosts {
		return errors.New("select between one and 100 explicitly pinned SSH targets")
	}
	seen := map[string]bool{}
	for _, host := range hosts {
		if err := host.Validate(); err != nil {
			return err
		}
		if seen[host.Address] {
			return errors.New("an SSH target can appear only once")
		}
		seen[host.Address] = true
	}
	return nil
}
func (h Host) Validate() error {
	host, port, err := net.SplitHostPort(h.Address)
	n, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || host == "" || strings.TrimSpace(h.Address) != h.Address || strings.ContainsAny(host, "\x00\r\n /\\@%") || len(host) > 253 {
		return errors.New("SSH collection needs one canonical host:port per target")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		if address.String() != host {
			return errors.New("use a canonical SSH IP literal")
		}
	} else {
		for _, label := range strings.Split(host, ".") {
			if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return errors.New("use a bounded SSH DNS hostname")
			}
			for _, r := range label {
				if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
					return errors.New("use a lowercase ASCII SSH hostname")
				}
			}
		}
	}
	if !usernameRE.MatchString(h.Username) || h.Username == "root" {
		return errors.New("select a least-privilege non-root SSH collection account")
	}
	if !strings.HasPrefix(h.HostKeyFingerprint, "SHA256:") {
		return errors.New("pin the SSH server host key fingerprint")
	}
	raw, err := base64.RawStdEncoding.Strict().DecodeString(strings.TrimPrefix(h.HostKeyFingerprint, "SHA256:"))
	if err != nil || len(raw) != 32 {
		return errors.New("pin a canonical SHA256 SSH host-key fingerprint")
	}
	if !strings.HasPrefix(h.CredentialRef, "secret://") || len(h.CredentialRef) <= len("secret://") || len(h.CredentialRef) > 512 || strings.ContainsAny(h.CredentialRef, "\x00\r\n\t ") {
		return errors.New("use a vault secret:// credential reference, never a key value")
	}
	return nil
}
func (c Config) Resolve() Command {
	return Command{JobKind: Destination, Execution: "relay", RequiredAgentRole: "network", RequiredAgentID: c.RelayAgentID, Segment: c.Segment, AllowRFC1918: c.AllowRFC1918, AllowLoopback: c.AllowLoopback, Hosts: append([]Host(nil), c.Hosts...)}
}
func (c Command) Validate() error {
	if !canonicalID(c.ID) || !canonicalID(c.SourceID) || !canonicalID(c.RequiredAgentID) || c.JobKind != Destination || c.Execution != "relay" || c.RequiredAgentRole != "network" {
		return errors.New("SSH collection command must bind its exact source, run and network relay")
	}
	if c.ScheduleID != nil && !canonicalID(*c.ScheduleID) || c.RetryOfRunID != "" && !canonicalID(c.RetryOfRunID) {
		return errors.New("SSH collection schedule/retry identity is invalid")
	}
	return validateScope(c.Segment, c.Hosts)
}
func (c Command) CredentialRefs() []string {
	set := map[string]bool{}
	for _, host := range c.Hosts {
		set[host.CredentialRef] = true
	}
	out := make([]string, 0, len(set))
	for ref := range set {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}
func (c Command) Digest() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	effect := c
	effect.RequestedBy = ""
	raw, err := json.Marshal(effect)
	if err != nil {
		return "", err
	}
	return "sha256:" + crypto.SHA256Hex(raw), nil
}
