// SPDX-License-Identifier: MPL-2.0

// Package plugincensus defines the small, metadata-only description of WASM
// connectors a verified network-relay runtime has actually loaded.
package plugincensus

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

const (
	// ExecutionContextNetworkRelayWASM says the module runs in the relay's
	// wazero sandbox, not in the control-plane process.
	ExecutionContextNetworkRelayWASM = "network_relay_wasm"
	MaxPlugins                       = 128
	maxConstraintsPerGrant           = 64
	maxMetadataBytes                 = 512
	signatureVersion                 = "trstctl-agent-plugin-census/v1\n"
)

// Grant is one effective host capability and its normalized resource fence.
// An empty Constraints list means the capability is intentionally unrestricted.
type Grant struct {
	Capability  string   `json:"capability"`
	Constraints []string `json:"constraints"`
}

// Entry is one module that passed provenance verification and was instantiated.
// Digest and Publisher are sha256: fingerprints, never module or key bytes.
type Entry struct {
	Name             string  `json:"name"`
	Digest           string  `json:"digest"`
	Publisher        string  `json:"publisher"`
	ExecutionContext string  `json:"execution_context"`
	Grants           []Grant `json:"grants"`
}

// Report is carried on the authenticated heartbeat. Signature is made by the
// same key behind the mTLS certificate over Statement.Canonical().
type Report struct {
	Plugins      []Entry `json:"plugins"`
	IssuedAtUnix int64   `json:"issued_at_unix"`
	Signature    []byte  `json:"signature"`
}

// Statement binds the metadata to the tenant and agent identities that both
// sides independently read from their own certificate.
type Statement struct {
	TenantID        string
	AgentCommonName string
	Plugins         []Entry
	IssuedAtUnix    int64
}

// Normalize validates bounds and returns one deterministic copy. The relay
// calls it before signing; the server requires the received body to already be
// in this form so normalization cannot change the meaning after signature.
func Normalize(entries []Entry) ([]Entry, error) {
	if len(entries) > MaxPlugins {
		return nil, fmt.Errorf("plugin census has %d entries; maximum is %d", len(entries), MaxPlugins)
	}
	out := make([]Entry, len(entries))
	seen := make(map[string]bool, len(entries))
	for i, in := range entries {
		if !safeToken(in.Name) {
			return nil, fmt.Errorf("plugin %d has invalid name", i)
		}
		if seen[in.Name] {
			return nil, fmt.Errorf("plugin %q is duplicated", in.Name)
		}
		seen[in.Name] = true
		if !sha256Fingerprint(in.Digest) || !sha256Fingerprint(in.Publisher) {
			return nil, fmt.Errorf("plugin %q requires lowercase sha256 digest and publisher fingerprints", in.Name)
		}
		if in.ExecutionContext != ExecutionContextNetworkRelayWASM {
			return nil, fmt.Errorf("plugin %q has unsupported execution context %q", in.Name, in.ExecutionContext)
		}
		out[i] = Entry{Name: in.Name, Digest: in.Digest, Publisher: in.Publisher, ExecutionContext: in.ExecutionContext}
		if len(in.Grants) > 3 {
			return nil, fmt.Errorf("plugin %q has too many grants", in.Name)
		}
		grantSeen := map[string]bool{}
		out[i].Grants = make([]Grant, len(in.Grants))
		for j, grant := range in.Grants {
			if grant.Capability != "fs.read" && grant.Capability != "fs.write" && grant.Capability != "net.dial" {
				return nil, fmt.Errorf("plugin %q has unknown capability %q", in.Name, grant.Capability)
			}
			if grantSeen[grant.Capability] {
				return nil, fmt.Errorf("plugin %q duplicates capability %q", in.Name, grant.Capability)
			}
			grantSeen[grant.Capability] = true
			if len(grant.Constraints) > maxConstraintsPerGrant {
				return nil, fmt.Errorf("plugin %q capability %q has too many constraints", in.Name, grant.Capability)
			}
			// The public contract is an array. Preserve that shape for an
			// unrestricted grant instead of letting encoding/json emit null.
			constraints := append([]string{}, grant.Constraints...)
			for _, constraint := range constraints {
				if constraint == "" || len(constraint) > maxMetadataBytes || strings.ContainsAny(constraint, "\r\n\x00") {
					return nil, fmt.Errorf("plugin %q capability %q has invalid constraint", in.Name, grant.Capability)
				}
			}
			sort.Strings(constraints)
			for k := 1; k < len(constraints); k++ {
				if constraints[k] == constraints[k-1] {
					return nil, fmt.Errorf("plugin %q capability %q duplicates a constraint", in.Name, grant.Capability)
				}
			}
			out[i].Grants[j] = Grant{Capability: grant.Capability, Constraints: constraints}
		}
		sort.Slice(out[i].Grants, func(a, b int) bool { return out[i].Grants[a].Capability < out[i].Grants[b].Capability })
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Validate requires an already-normalized statement.
func (s Statement) Validate() error {
	if s.TenantID == "" || s.AgentCommonName == "" || s.IssuedAtUnix <= 0 ||
		strings.ContainsAny(s.TenantID+s.AgentCommonName, "\r\n\x00") {
		return errors.New("plugin census statement identity or issued-at is invalid")
	}
	normalized, err := Normalize(s.Plugins)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(normalized, s.Plugins) {
		return errors.New("plugin census is not normalized")
	}
	return nil
}

// Canonical returns the only bytes that may be signed for this statement.
// Struct JSON has fixed field order and contains no maps; Normalize fixes all
// slice order before this method is used.
func (s Statement) Canonical() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(struct {
		TenantID        string  `json:"tenant_id"`
		AgentCommonName string  `json:"agent_common_name"`
		Plugins         []Entry `json:"plugins"`
		IssuedAtUnix    int64   `json:"issued_at_unix"`
	}{s.TenantID, s.AgentCommonName, s.Plugins, s.IssuedAtUnix})
	if err != nil {
		return nil, err
	}
	return append([]byte(signatureVersion), body...), nil
}

func safeToken(v string) bool {
	if len(v) == 0 || len(v) > 128 {
		return false
	}
	for i, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || (i > 0 && (r == '.' || r == '_' || r == '-')) {
			continue
		}
		return false
	}
	return true
}

func sha256Fingerprint(v string) bool {
	raw, err := hex.DecodeString(strings.TrimPrefix(v, "sha256:"))
	return strings.HasPrefix(v, "sha256:") && v == strings.ToLower(v) && err == nil && len(raw) == 32
}
