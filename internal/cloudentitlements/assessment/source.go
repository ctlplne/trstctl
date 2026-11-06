// SPDX-License-Identifier: BUSL-1.1
package assessment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"

	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
	"trstctl.com/trstctl/internal/crypto/awssignin"
	"trstctl.com/trstctl/internal/netsec"
)

// SourceConfig carries no credential value or arbitrary host file path. The
// operator approves an env reference whose value names an owner-only STS file.
type SourceConfig struct {
	Endpoint             string             `json:"endpoint,omitempty"`
	Region               string             `json:"region,omitempty"`
	CAPEM                string             `json:"ca_pem,omitempty"`
	SessionFileRef       string             `json:"session_file_ref"`
	AllowPrivateEndpoint bool               `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs   []string           `json:"private_egress_cidrs,omitempty"`
	Principals           []awsiam.Selection `json:"principals"`
	Input                Input              `json:"assessment"`
}

func DecodeSource(raw []byte) (SourceConfig, error) {
	var cfg SourceConfig
	if len(raw) == 0 || len(raw) > 768<<10 {
		return cfg, errors.New("cloud machine source exceeds configuration bound")
	}
	if err := validateSourceObject(raw); err != nil {
		return cfg, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil || len(bytes.TrimSpace(raw[decoder.InputOffset():])) != 0 {
		return cfg, errors.New("invalid cloud machine source configuration")
	}
	if !strings.HasPrefix(cfg.SessionFileRef, "env:") || len(cfg.SessionFileRef) <= 4 || len(cfg.SessionFileRef) > 256 {
		return cfg, errors.New("session_file_ref must name an operator-approved env: reference")
	}
	for _, r := range strings.TrimPrefix(cfg.SessionFileRef, "env:") {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return cfg, errors.New("invalid session file env reference")
		}
	}
	if len(cfg.Principals) == 0 || len(cfg.Principals) > awsiam.MaxPrincipals {
		return cfg, errors.New("select between 1 and 256 workload principals")
	}
	if len(cfg.CAPEM) > 64<<10 || len(cfg.PrivateEgressCIDRs) > 32 {
		return cfg, errors.New("cloud reader trust/egress configuration exceeds bound")
	}
	for _, cidr := range cfg.PrivateEgressCIDRs {
		if _, err := netsec.ParseEgressAllowPrefix(cidr); err != nil {
			return cfg, err
		}
	}
	if len(cfg.PrivateEgressCIDRs) > 0 && !cfg.AllowPrivateEndpoint {
		return cfg, errors.New("private CIDRs require explicit private endpoint opt-in")
	}
	if err := Validate(cfg.Input); err != nil {
		return cfg, err
	}
	// New performs only endpoint validation. No credentials or sockets are used.
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://iam.amazonaws.com"
	}
	_, err := awsiam.New(awsiam.Config{Endpoint: endpoint, Region: cfg.Region, AllowInsecureLoopback: cfg.AllowPrivateEndpoint, UseCredentials: func(context.Context, func(awssignin.Credentials) error) error { return errors.New("validation only") }})
	if err != nil {
		return cfg, err
	}
	seen := map[awsiam.Selection]bool{}
	for _, principal := range cfg.Principals {
		if seen[principal] || len(principal.Name) == 0 || len(principal.Name) > 128 || (principal.Kind != "iam_user" && principal.Kind != "iam_role") {
			return cfg, errors.New("invalid or duplicate selected workload principal")
		}
		seen[principal] = true
	}
	return cfg, nil
}

// DecodeAssessment accepts only bounded typed public facts for graph joins.
// Fingerprint verification and native-source/run verification remain mandatory.
func DecodeAssessment(raw []byte) (Assessment, error) {
	var out Assessment
	if len(raw) == 0 || len(raw) > 2<<20 {
		return out, errors.New("assessment exceeds graph evidence bound")
	}
	if json.Unmarshal(raw, &out) != nil || out.Version != 1 || out.Provider != "aws-iam" {
		return out, errors.New("invalid cloud machine assessment")
	}
	return out, nil
}

// encoding/json matches struct field names without case. Exact names here keep
// an alternate spelling from bypassing API approval of *_ref fields.
func validateSourceObject(raw []byte) error {
	allowed := map[string]bool{"endpoint": true, "region": true, "ca_pem": true, "session_file_ref": true, "allow_private_endpoint": true, "private_egress_cidrs": true, "principals": true, "assessment": true}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("source configuration must be an object")
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err = decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || seen[key] {
			return errors.New("unknown, ambiguous or duplicate source configuration field")
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return errors.New("invalid source field")
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || len(bytes.TrimSpace(raw[decoder.InputOffset():])) != 0 {
		return errors.New("invalid source object framing")
	}
	return nil
}
