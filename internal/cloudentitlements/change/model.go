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
	ReplaceKey       = "replace_key"
	Preparing        = "preparing_replacement"
	WaitingAdoption  = "waiting_adoption"
	TightenPolicy    = "tighten_policy"
	AwaitingApproval = "awaiting_approval"
	Queued           = "queued"
	Verified         = "verified"
	Failed           = "failed"
	Destination      = "cloud.machine.change"
)

type Intent struct {
	ReplacementRoleAllowPrivate         bool     `json:"replacement_role_allow_private,omitempty"`
	ReplacementProviderID               string   `json:"replacement_provider_id,omitempty"`
	ReplacementProviderRevision         string   `json:"replacement_provider_revision,omitempty"`
	ReplacementRole                     string   `json:"replacement_role,omitempty"`
	ReplacementRoleARN                  string   `json:"replacement_role_arn,omitempty"`
	ReplacementRoleID                   string   `json:"replacement_role_id,omitempty"`
	ReplacementRoleFindingID            string   `json:"replacement_role_finding_id,omitempty"`
	ReplacementRoleFindingFingerprint   string   `json:"replacement_role_finding_fingerprint,omitempty"`
	ReplacementRoleSourceID             string   `json:"replacement_role_source_id,omitempty"`
	ReplacementRoleSourceFingerprint    string   `json:"replacement_role_source_fingerprint,omitempty"`
	ReplacementRoleAuthorityFingerprint string   `json:"replacement_role_authority_fingerprint,omitempty"`
	Consumer                            string   `json:"consumer,omitempty"`
	ConsumerSubject                     string   `json:"consumer_subject,omitempty"`
	ReplacementExpectedVersion          int      `json:"replacement_expected_version,omitempty"`
	ReplacementTTLSeconds               int      `json:"replacement_ttl_seconds,omitempty"`
	RequiredApprovals                   int      `json:"required_approvals"`
	Action                              string   `json:"action"`
	SourceID                            string   `json:"source_id"`
	FindingID                           string   `json:"finding_id"`
	FindingFingerprint                  string   `json:"finding_fingerprint"`
	SourceFingerprint                   string   `json:"source_fingerprint"`
	PrincipalARN                        string   `json:"principal_arn"`
	PrincipalID                         string   `json:"principal_id"`
	PrincipalKind                       string   `json:"principal_kind"`
	PrincipalName                       string   `json:"principal_name"`
	Endpoint                            string   `json:"endpoint"`
	Region                              string   `json:"region"`
	CAPEM                               string   `json:"ca_pem,omitempty"`
	AllowPrivateEndpoint                bool     `json:"allow_private_endpoint"`
	PrivateEgressCIDRs                  []string `json:"private_egress_cidrs,omitempty"`
	WriterSessionFileRef                string   `json:"writer_session_file_ref"`
	AccessKeyID                         string   `json:"access_key_id,omitempty"`
	PolicyName                          string   `json:"policy_name,omitempty"`
	// Bytes retain the exact proposed public document through JSONB storage.
	PolicyDocument []byte `json:"policy_document,omitempty"`
	PolicySHA256   string `json:"policy_sha256,omitempty"`
	Reason         string `json:"reason"`
}
type Result struct {
	ReplacementCommandID    string     `json:"replacement_command_id,omitempty"`
	ReplacementLeaseID      string     `json:"replacement_lease_id,omitempty"`
	ReplacementVersion      int        `json:"replacement_version,omitempty"`
	ReplacementExpiresAt    *time.Time `json:"replacement_expires_at,omitempty"`
	ReplacementNativeRoleID string     `json:"replacement_native_role_id,omitempty"`
	PreparationPhase        string     `json:"preparation_phase,omitempty"`
	EffectUncertain         bool       `json:"effect_uncertain,omitempty"`
	KeyAbsent               bool       `json:"key_absent,omitempty"`
	PolicyMatches           bool       `json:"policy_matches,omitempty"`
	Postcondition           string     `json:"postcondition,omitempty"`
	CheckedAt               time.Time  `json:"checked_at"`
	Error                   string     `json:"error,omitempty"`
}
type Adoption struct {
	Consumer   string    `json:"consumer"`
	Subject    string    `json:"subject"`
	Name       string    `json:"name"`
	Version    int       `json:"version"`
	EventID    string    `json:"event_id"`
	Sequence   uint64    `json:"sequence"`
	VerifiedAt time.Time `json:"verified_at"`
}

type Record struct {
	Adoption          *Adoption `json:"adoption,omitempty"`
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
	return state == AwaitingApproval || state == Queued || state == Preparing || state == WaitingAdoption || state == Verified || state == Failed
}

// PublicationBinding preserves the existing 64-hex child-command contract.
func PublicationBinding(plan Record) string {
	return crypto.SHA256Hex([]byte("cloud-replacement\x00" + plan.TenantID + "\x00" + plan.ID + "\x00" + plan.IntentDigest))
}
