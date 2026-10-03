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
	// but AWS can still accept its previously issued STS session until native expiry.
	ErrAWSSTSSessionActive = errors.New("dynsecret aws-sts: session remains valid until AWS expiry")
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
}

type AWSSTSBackend struct {
	query    *AWSIAMBackend
	roleARNs map[string]string
}

type awsSTSRef struct {
	RoleARN       string    `json:"role_arn"`
	SessionName   string    `json:"session_name"`
	AssumedRoleID string    `json:"assumed_role_id"`
	AccessKeyID   string    `json:"access_key_id"`
	Expiration    time.Time `json:"expiration"`
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
	return &AWSSTSBackend{query: query, roleARNs: cloneStringMap(cfg.RoleARNs)}, nil
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
	raw, err := b.query.callService(ctx, map[string]string{
		"Action": "AssumeRole", "Version": "2011-06-15", "RoleArn": roleARN,
		"RoleSessionName": session, "DurationSeconds": strconv.Itoa(seconds),
	}, awsSTSService)
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
		AccessKeyID: issued.AccessKeyID, Expiration: expiration,
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

// Revoke cannot claim remote invalidation: STS has no per-credential delete
// operation. The durable revoke outbox keeps the provider status pending until
// the native expiry has passed; only then is passive invalidation complete.
func (b *AWSSTSBackend) Revoke(_ context.Context, ref string) error {
	return CheckAWSSTSExpiration(ref, b.query.now())
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
// It enables an operator to see when passive AWS revocation can complete.
func AWSSTSExpiration(ref string) (time.Time, bool) {
	var issued awsSTSRef
	if err := json.Unmarshal([]byte(ref), &issued); err != nil || !awsSTSRoleARN.MatchString(issued.RoleARN) || issued.SessionName == "" || issued.AssumedRoleID == "" || issued.AccessKeyID == "" || issued.Expiration.IsZero() {
		return time.Time{}, false
	}
	return issued.Expiration, true
}

func (b *AWSSTSBackend) Close() { b.query.Close() }
