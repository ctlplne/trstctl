// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

const awsSTSService = "sts"

var (
	awsSTSRoleARN = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$`)
	// ErrAWSSTSSessionActive means the caller's access has been closed in trstctl,
	// but AWS can still accept its previously issued STS session until native
	// expiry. It is an ErrNativeExpiryPending.
	ErrAWSSTSSessionActive = fmt.Errorf("dynsecret aws-sts: session remains valid until AWS expiry: %w", ErrNativeExpiryPending)
)

// AWSSTSConfig maps each operator-approved role to an assumable AWS IAM role.
// The caller authority may be a short-lived session; it is read from a file or
// tenant secret at delivery time by the server and locked only for this call.
type AWSSTSConfig struct {
	Endpoint        string
	HTTPClient      HTTPDoer
	Region          string
	AccessKeyID     string
	SecretAccessKey []byte
	SessionToken    []byte
	SessionPrefix   string
	RoleARNs        map[string]string
	// IAMEndpoint is where ResolveAccess lists an assumed role's policies
	// (G2); empty means AWS IAM for the region's partition. IAMHTTPClient
	// reaches it (HTTPClient when nil).
	IAMEndpoint   string
	IAMHTTPClient HTTPDoer
	// RevokeWithDenyPolicy ends a revoked lease's session before its expiry
	// with an inline deny policy on the role for that one session (N3). The
	// credentials then also need iam:PutRolePolicy, iam:GetRolePolicy,
	// iam:ListRolePolicies and iam:DeleteRolePolicy on the bound roles.
	RevokeWithDenyPolicy bool
	// AllowRoleChaining lets a lease's session assume other roles (N3-L3).
	// Without it every lease's AssumeRole passes awsSTSNoChainingSessionPolicy.
	// A chained session runs as another role, which neither a denial on the
	// lease's role nor the lease's expiry reaches: with it, a revocation waits
	// AWSSTSChainedSessionMaxDuration past the session's expiry, and it can't
	// be combined with RevokeWithDenyPolicy.
	AllowRoleChaining bool
	// DenyAccessKeyID, DenySecretAccessKey and DenySessionToken (N3-L1) sign
	// the denial writes, their read back and pruning when set; the issuing
	// credential then needs no IAM write permission. Empty uses the issuing
	// credential.
	DenyAccessKeyID     string
	DenySecretAccessKey []byte
	DenySessionToken    []byte
}

// AWSSTSChainedSessionMaxDuration is the longest a role session chained from
// another can run: AWS limits a role-chaining session to one hour.
const AWSSTSChainedSessionMaxDuration = time.Hour

// awsSTSNoChainingSessionPolicy is the session policy a lease's AssumeRole
// passes unless the provider allows role chaining (N3-L3). A session's
// permissions are its role's intersected with its session policy: the Allow
// keeps everything the role allows, and the Deny takes sts:AssumeRole away,
// so a lease can't chain into another role whose session its revocation would
// not reach.
const awsSTSNoChainingSessionPolicy = `{"Version":"2012-10-17","Statement":[` +
	`{"Sid":"TrstctlLeaseKeepsItsRole","Effect":"Allow","Action":"*","Resource":"*"},` +
	`{"Sid":"TrstctlLeaseCannotChainRoles","Effect":"Deny","Action":"sts:AssumeRole","Resource":"*"}]}`

type AWSSTSBackend struct {
	query *AWSIAMBackend
	iam   *AWSIAMBackend
	// deny signs the denials (N3-L1): its own credential, or iam's.
	deny         *AWSIAMBackend
	roleARNs     map[string]string
	denyPolicy   bool
	roleChaining bool
}

type awsSTSRef struct {
	RoleARN       string    `json:"role_arn"`
	SessionName   string    `json:"session_name"`
	AssumedRoleID string    `json:"assumed_role_id"`
	AccessKeyID   string    `json:"access_key_id"`
	Expiration    time.Time `json:"expiration"`
	// RoleChaining records that the session was issued able to assume other
	// roles (N3-L3), so its revocation waits for a chained session too.
	RoleChaining bool `json:"role_chaining,omitempty"`
}

// NewAWSSTSBackend builds a bounded AssumeRole issuer. It does not create IAM
// users or permanent access keys. A local HTTP test double proves the wire
// contract; an AWS account is required to qualify actual AWS behavior.
func NewAWSSTSBackend(cfg AWSSTSConfig) (*AWSSTSBackend, error) {
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://sts." + cfg.Region + ".amazonaws.com"
	}
	if len(cfg.RoleARNs) == 0 {
		return nil, errors.New("dynsecret aws-sts: at least one role ARN is required")
	}
	if cfg.AllowRoleChaining && cfg.RevokeWithDenyPolicy {
		return nil, errors.New("dynsecret aws-sts: allow_role_chaining can't be combined with revoke_with_deny_policy: a denial on the lease's role does not reach a session chained into another role")
	}
	for role, arn := range cfg.RoleARNs {
		if strings.TrimSpace(role) == "" || !awsSTSRoleARN.MatchString(arn) {
			return nil, fmt.Errorf("dynsecret aws-sts: role %q requires a full IAM role ARN", role)
		}
	}
	query, err := NewAWSIAMBackend(AWSIAMConfig{
		Endpoint: cfg.Endpoint, HTTPClient: cfg.HTTPClient, Region: cfg.Region,
		AccessKeyID: cfg.AccessKeyID, SecretAccessKey: cfg.SecretAccessKey,
		SessionToken: cfg.SessionToken, UsernamePrefix: cfg.SessionPrefix,
	})
	if err != nil {
		return nil, fmt.Errorf("dynsecret aws-sts: initialize signed query client: %w", err)
	}
	iamEndpoint, iamRegion := AWSIAMEndpointFor(cfg.Region, cfg.IAMEndpoint)
	iamClient := cfg.IAMHTTPClient
	if iamClient == nil {
		iamClient = cfg.HTTPClient
	}
	iam, err := NewAWSIAMBackend(AWSIAMConfig{
		Endpoint: iamEndpoint, HTTPClient: iamClient, Region: iamRegion,
		AccessKeyID: cfg.AccessKeyID, SecretAccessKey: cfg.SecretAccessKey,
		SessionToken: cfg.SessionToken, UsernamePrefix: cfg.SessionPrefix,
	})
	if err != nil {
		query.Close()
		return nil, fmt.Errorf("dynsecret aws-sts: initialize IAM read client: %w", err)
	}
	deny := iam
	if cfg.DenyAccessKeyID != "" {
		if !cfg.RevokeWithDenyPolicy {
			query.Close()
			iam.Close()
			return nil, errors.New("dynsecret aws-sts: a denial credential needs revoke_with_deny_policy")
		}
		deny, err = NewAWSIAMBackend(AWSIAMConfig{
			Endpoint: iamEndpoint, HTTPClient: iamClient, Region: iamRegion,
			AccessKeyID: cfg.DenyAccessKeyID, SecretAccessKey: cfg.DenySecretAccessKey,
			SessionToken: cfg.DenySessionToken, UsernamePrefix: cfg.SessionPrefix,
		})
		if err != nil {
			query.Close()
			iam.Close()
			return nil, fmt.Errorf("dynsecret aws-sts: initialize the denial client: %w", err)
		}
	}
	return &AWSSTSBackend{query: query, iam: iam, deny: deny, roleARNs: cloneStringMap(cfg.RoleARNs),
		denyPolicy: cfg.RevokeWithDenyPolicy, roleChaining: cfg.AllowRoleChaining}, nil
}

func (b *AWSSTSBackend) Create(context.Context, string) (string, []byte, error) {
	return "", nil, errors.New("dynsecret aws-sts: lease identity and native TTL are required")
}

func (b *AWSSTSBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	if req.LeaseID == "" || req.TTL <= 0 || req.TTL > 12*time.Hour {
		return "", nil, errors.New("dynsecret aws-sts: lease ID and native TTL between 15 minutes and 12 hours are required")
	}
	seconds := int((req.TTL + time.Second - 1) / time.Second)
	if seconds < 900 || seconds > 43200 {
		return "", nil, errors.New("dynsecret aws-sts: rounded native TTL must be between 900 and 43200 seconds")
	}
	roleARN := b.roleARNs[req.Role]
	if roleARN == "" {
		return "", nil, fmt.Errorf("dynsecret aws-sts: role %q is not configured", req.Role)
	}
	session, err := scopedNameForRequest(b.query.usernamePrefix, req, 64, "-")
	if err != nil {
		return "", nil, err
	}
	started := b.query.now().UTC()
	params := map[string]string{
		"Action": "AssumeRole", "Version": "2011-06-15", "RoleArn": roleARN,
		"RoleSessionName": session, "DurationSeconds": strconv.Itoa(seconds),
	}
	if !b.roleChaining {
		params["Policy"] = awsSTSNoChainingSessionPolicy
	}
	raw, err := b.query.callService(ctx, params, awsSTSService)
	if err != nil {
		return "", nil, fmt.Errorf("dynsecret aws-sts: AssumeRole: %w", err)
	}
	var response struct {
		Result struct {
			Credentials struct {
				AccessKeyID     string           `xml:"AccessKeyId"`
				SecretAccessKey secret.JSONBytes `xml:"SecretAccessKey"`
				SessionToken    secret.JSONBytes `xml:"SessionToken"`
				Expiration      string           `xml:"Expiration"`
			} `xml:"Credentials"`
			AssumedRoleUser struct {
				ID string `xml:"AssumedRoleId"`
			} `xml:"AssumedRoleUser"`
		} `xml:"AssumeRoleResult"`
	}
	defer secret.Wipe(raw)
	defer func() {
		secret.Wipe(response.Result.Credentials.SecretAccessKey)
		secret.Wipe(response.Result.Credentials.SessionToken)
	}()
	if err := xml.Unmarshal(raw, &response); err != nil {
		return "", nil, fmt.Errorf("dynsecret aws-sts: decode AssumeRole: %w", err)
	}
	issued := response.Result.Credentials
	expiration, err := time.Parse(time.RFC3339, issued.Expiration)
	if err != nil || issued.AccessKeyID == "" || len(issued.SecretAccessKey) == 0 || len(issued.SessionToken) == 0 || response.Result.AssumedRoleUser.ID == "" ||
		expiration.Before(started.Add(req.TTL).Add(-2*time.Second)) {
		return "", nil, errors.New("dynsecret aws-sts: incomplete or shorter-than-requested AssumeRole response")
	}
	refBytes, err := json.Marshal(awsSTSRef{
		RoleARN: roleARN, SessionName: session, AssumedRoleID: response.Result.AssumedRoleUser.ID,
		AccessKeyID: issued.AccessKeyID, Expiration: expiration, RoleChaining: b.roleChaining,
	})
	if err != nil {
		return "", nil, err
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- this is the reveal-once AWS STS credential payload; the caller seals it before storage (CWE-200)
		AccessKeyID     string           `json:"access_key_id"`
		SecretAccessKey secret.JSONBytes `json:"secret_access_key"`
		SessionToken    secret.JSONBytes `json:"session_token"`
		Expiration      time.Time        `json:"expiration"`
	}{issued.AccessKeyID, issued.SecretAccessKey, issued.SessionToken, expiration})
	if err != nil {
		return "", nil, err
	}
	return string(refBytes), credential, nil
}

// Revoke cannot claim remote invalidation by itself: STS has no
// per-credential delete operation. Without revoke_with_deny_policy the durable
// revoke outbox keeps the provider status pending until the native expiry has
// passed; with it, RevokeMethod denies the session through its role (N3).
func (b *AWSSTSBackend) Revoke(ctx context.Context, ref string) error {
	_, err := b.RevokeMethod(ctx, ref)
	return err
}

// CheckAWSSTSExpiration is local-only and requires no AWS administrator key.
// It refuses to call a passive timeout an active remote revocation.
func CheckAWSSTSExpiration(ref string, now time.Time) error {
	expiration, ok := AWSSTSExpiration(ref)
	if !ok {
		return errors.New("dynsecret aws-sts: invalid session reference")
	}
	if now.Before(expiration) {
		return ErrAWSSTSSessionActive
	}
	return nil
}

// AWSSTSExpiration extracts only public session metadata from a provider ref.
// It enables an operator to see when passive AWS revocation can complete: the
// session's expiry, or for a session issued able to chain roles, an hour
// after it, the longest a session chained from it can run (N3-L3).
func AWSSTSExpiration(ref string) (time.Time, bool) {
	var issued awsSTSRef
	if err := json.Unmarshal([]byte(ref), &issued); err != nil || !awsSTSRoleARN.MatchString(issued.RoleARN) || issued.SessionName == "" || issued.AssumedRoleID == "" || issued.AccessKeyID == "" || issued.Expiration.IsZero() {
		return time.Time{}, false
	}
	if issued.RoleChaining {
		return issued.Expiration.Add(AWSSTSChainedSessionMaxDuration), true
	}
	return issued.Expiration, true
}

// AWSSTSRoleChaining reports whether a lease's session was issued able to
// assume other roles (N3-L3).
func AWSSTSRoleChaining(ref string) bool {
	var issued awsSTSRef
	if _, ok := AWSSTSExpiration(ref); !ok || json.Unmarshal([]byte(ref), &issued) != nil {
		return false
	}
	return issued.RoleChaining
}

func (b *AWSSTSBackend) Close() {
	b.query.Close()
	if b.iam != nil {
		b.iam.Close()
	}
	if b.deny != nil && b.deny != b.iam {
		b.deny.Close()
	}
}
