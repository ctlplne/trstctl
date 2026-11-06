// SPDX-License-Identifier: BUSL-1.1
// Package awsiam captures selected workload identities through read-only IAM
// calls. Organization/resource/activity evidence has separate explicit coverage.
package awsiam

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"

	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/crypto/awssignin"
)

const MaxPrincipals = 256

type Selection struct {
	Kind awspolicy.PrincipalKind `json:"kind"`
	Name string                  `json:"name"`
}
type Config struct {
	Endpoint              string
	Region                string
	CAPEM                 []byte
	AllowInsecureLoopback bool
	PrivateEgressCIDRs    []netip.Prefix
	// Credentials are borrowed separately for each call, not retained by Client.
	UseCredentials func(context.Context, func(awssignin.Credentials) error) error
	Now            func() time.Time
}
type Key struct {
	ID              string             `json:"id"`
	Status          string             `json:"status"`
	Created         time.Time          `json:"created_at"`
	LastUsed        *time.Time         `json:"last_used_at,omitempty"`
	LastUsedService string             `json:"last_used_service,omitempty"`
	LastUsedRegion  string             `json:"last_used_region,omitempty"`
	LastUseCoverage awspolicy.Coverage `json:"last_use_coverage"`
}
type Identity struct {
	Principal      awspolicy.Principal `json:"principal"`
	Name           string              `json:"name"`
	Created        time.Time           `json:"created_at"`
	LastUsed       *time.Time          `json:"last_used_at,omitempty"`
	Keys           []Key               `json:"keys,omitempty"`
	TrustDocument  json.RawMessage     `json:"trust_document,omitempty"`
	Evidence       awspolicy.Evidence  `json:"-"`
	PolicyReceipts []PolicyReceipt     `json:"policies"`
	Gaps           []string            `json:"gaps"`
}
type PolicyReceipt struct {
	RawDocument []byte          `json:"raw_document"`
	Category    string          `json:"category"`
	ID          string          `json:"id"`
	Version     string          `json:"version,omitempty"`
	SHA256      string          `json:"sha256"`
	Document    json.RawMessage `json:"document"`
}
type Capture struct {
	CollectedAt time.Time  `json:"collected_at"`
	Identities  []Identity `json:"identities"`
	Calls       int        `json:"calls"`
}
