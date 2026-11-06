// SPDX-License-Identifier: BUSL-1.1
// Package change defines immutable, reviewed cloud machine change intents.
// Credential values never belong in these records.
package change

import (
	"encoding/json"
	"errors"
	"time"
	"trstctl.com/trstctl/internal/crypto"
)

const (
	RevokeKey        = "revoke_key"
	TightenPolicy    = "tighten_policy"
	AwaitingApproval = "awaiting_approval"
	Queued           = "queued"
	Verified         = "verified"
	Failed           = "failed"
	Destination      = "cloud.machine.change"
)

type Intent struct {
	RequiredApprovals    int      `json:"required_approvals"`
	Action               string   `json:"action"`
	SourceID             string   `json:"source_id"`
	FindingID            string   `json:"finding_id"`
	FindingFingerprint   string   `json:"finding_fingerprint"`
	SourceFingerprint    string   `json:"source_fingerprint"`
	PrincipalARN         string   `json:"principal_arn"`
	PrincipalID          string   `json:"principal_id"`
	PrincipalKind        string   `json:"principal_kind"`
	PrincipalName        string   `json:"principal_name"`
	Endpoint             string   `json:"endpoint"`
	Region               string   `json:"region"`
	CAPEM                string   `json:"ca_pem,omitempty"`
	AllowPrivateEndpoint bool     `json:"allow_private_endpoint"`
	PrivateEgressCIDRs   []string `json:"private_egress_cidrs,omitempty"`
	WriterSessionFileRef string   `json:"writer_session_file_ref"`
	AccessKeyID          string   `json:"access_key_id,omitempty"`
	PolicyName           string   `json:"policy_name,omitempty"`
	// Bytes retain the exact proposed public document through JSONB storage.
	PolicyDocument []byte `json:"policy_document,omitempty"`
	PolicySHA256   string `json:"policy_sha256,omitempty"`
	Reason         string `json:"reason"`
}
type Result struct {
	EffectUncertain bool      `json:"effect_uncertain,omitempty"`
	KeyAbsent       bool      `json:"key_absent,omitempty"`
	PolicyMatches   bool      `json:"policy_matches,omitempty"`
	Postcondition   string    `json:"postcondition,omitempty"`
	CheckedAt       time.Time `json:"checked_at"`
	Error           string    `json:"error,omitempty"`
}
type Record struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	Intent            Intent    `json:"intent"`
	State             string    `json:"state"`
	ApprovalRequestID string    `json:"approval_request_id"`
	IntentDigest      string    `json:"intent_digest"`
	RequestedBy       string    `json:"requested_by"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	Result            *Result   `json:"result,omitempty"`
	EventSequence     uint64    `json:"-"`
}

func Digest(intent Intent) (string, error) {
	raw, err := json.Marshal(intent)
	if err != nil {
		return "", err
	}
	if len(raw) > 256<<10 {
		return "", errors.New("cloud change intent exceeds 256 KiB")
	}
	return crypto.SHA256Hex(raw), nil
}
func ValidState(state string) bool {
	return state == AwaitingApproval || state == Queued || state == Verified || state == Failed
}
