// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

const (
	awsHoneyPolicyName = "trstctl-honeytoken-deny-all"
	awsHoneyTagName    = "trstctl-honeytoken-owner"
	awsHoneyPath       = "/trstctl/honeytokens/"
	awsHoneyDenyAll    = `{"Version":"2012-10-17","Statement":[{"Sid":"DenyAllUse","Effect":"Deny","Action":"*","Resource":"*"}]}`
)

var awsAccountID = regexp.MustCompile(`^[0-9]{12}$`)

// AWSHoneyConfig is the operator-owned IAM authority for a single AWS account.
// The caller must hold narrowly scoped IAM user, inline-policy, and key lifecycle
// permissions. OwnerTag is an opaque tenant/decoy identifier used to refuse a
// colliding, unowned IAM user on retry or retirement.
type AWSHoneyConfig struct {
	Endpoint        string
	HTTPClient      HTTPDoer
	Region          string
	AccountID       string
	AccessKeyID     string
	SecretAccessKey []byte
	SessionToken    []byte
	UsernamePrefix  string
	OwnerTag        string
}

// AWSHoneyBackend creates a real IAM access key that is unusable for privileged
// work. The explicit deny policy is installed and read back before a key exists.
// Every call to this backend must be made by a durable outbox worker.
type AWSHoneyBackend struct {
	query     *AWSIAMBackend
	accountID string
	ownerTag  string
}

type awsHoneyRef struct {
	AccountID   string `json:"account_id"`
	DecoyID     string `json:"decoy_id"`
	UserName    string `json:"user_name"`
	AccessKeyID string `json:"access_key_id"`
	OwnerTag    string `json:"owner_tag"`
}

func NewAWSHoneyBackend(cfg AWSHoneyConfig) (*AWSHoneyBackend, error) {
	if !awsAccountID.MatchString(cfg.AccountID) || cfg.OwnerTag == "" || len(cfg.OwnerTag) > 128 || strings.ContainsAny(cfg.OwnerTag, "\r\n\t ") {
		return nil, errors.New("aws honeytoken: account ID and opaque owner tag are required")
	}
	query, err := NewAWSIAMBackend(AWSIAMConfig{
		Endpoint: cfg.Endpoint, HTTPClient: cfg.HTTPClient, Region: cfg.Region,
		AccessKeyID: cfg.AccessKeyID, SecretAccessKey: cfg.SecretAccessKey,
		SessionToken: cfg.SessionToken, UsernamePrefix: cfg.UsernamePrefix,
	})
	if err != nil {
		return nil, fmt.Errorf("aws honeytoken: initialize IAM query client: %w", err)
	}
	return &AWSHoneyBackend{query: query, accountID: cfg.AccountID, ownerTag: cfg.OwnerTag}, nil
}

func (b *AWSHoneyBackend) Close() { b.query.Close() }

// Create reconciles only this decoy's tagged stable IAM user. A lost response
// can therefore be retried without leaving another active key. A name collision
// with an unowned user fails closed and is never deleted.
func (b *AWSHoneyBackend) Create(ctx context.Context, decoyID string) (string, []byte, error) {
	if decoyID == "" {
		return "", nil, errors.New("aws honeytoken: decoy ID required")
	}
	user, err := scopedNameForRequest(b.query.usernamePrefix, GenerateRequest{LeaseID: decoyID, Role: "honeytoken"}, 64, "_")
	if err != nil {
		return "", nil, err
	}
	owned, err := b.getOwnedUser(ctx, user)
	if err != nil {
		return "", nil, err
	}
	if owned {
		if err := b.deleteOwnedUser(ctx, user); err != nil {
			return "", nil, fmt.Errorf("aws honeytoken: reconcile old key before retry: %w", err)
		}
	}
	raw, err := b.query.call(ctx, map[string]string{
		"Action": "CreateUser", "Version": "2010-05-08", "UserName": user,
		"Path": awsHoneyPath, "Tags.member.1.Key": awsHoneyTagName,
		"Tags.member.1.Value": b.ownerTag,
	})
	if err != nil {
		return "", nil, fmt.Errorf("aws honeytoken: create IAM user: %w", err)
	}
	var created struct {
		Result struct {
			User struct {
				ARN string `xml:"Arn"`
			} `xml:"User"`
		} `xml:"CreateUserResult"`
	}
	decodeErr := xml.Unmarshal(raw, &created)
	secret.Wipe(raw)
	if decodeErr != nil || !b.expectedUserARN(created.Result.User.ARN, user) {
		// Unknown account ownership is too dangerous to clean up blindly.
		return "", nil, errors.New("aws honeytoken: IAM user response does not prove the configured account and path")
	}
	if err := b.waitForIAMReadback(ctx, "IAM user ownership", func() (bool, error) {
		return b.getOwnedUser(ctx, user)
	}); err != nil {
		return "", nil, err
	}
	if _, err := b.query.call(ctx, map[string]string{
		"Action": "PutUserPolicy", "Version": "2010-05-08", "UserName": user,
		"PolicyName": awsHoneyPolicyName, "PolicyDocument": awsHoneyDenyAll,
	}); err != nil {
		_ = b.deleteOwnedUser(ctx, user)
		return "", nil, fmt.Errorf("aws honeytoken: install deny-all policy before key creation: %w", err)
	}
	if err := b.waitForIAMReadback(ctx, "deny-all policy", func() (bool, error) {
		err := b.verifyDenyAll(ctx, user)
		return err == nil, err
	}); err != nil {
		_ = b.deleteOwnedUser(ctx, user)
		return "", nil, err
	}
	raw, err = b.query.call(ctx, map[string]string{
		"Action": "CreateAccessKey", "Version": "2010-05-08", "UserName": user,
	})
	if err != nil {
		_ = b.deleteOwnedUser(ctx, user)
		return "", nil, fmt.Errorf("aws honeytoken: create access key: %w", err)
	}
	var key struct {
		Result struct {
			AccessKey struct {
				ID     string           `xml:"AccessKeyId"`
				Secret secret.JSONBytes `xml:"SecretAccessKey"`
			} `xml:"AccessKey"`
		} `xml:"CreateAccessKeyResult"`
	}
	defer secret.Wipe(raw)
	defer func() { secret.Wipe(key.Result.AccessKey.Secret) }()
	if err := xml.Unmarshal(raw, &key); err != nil || key.Result.AccessKey.ID == "" || len(key.Result.AccessKey.Secret) == 0 {
		_ = b.deleteOwnedUser(ctx, user)
		return "", nil, errors.New("aws honeytoken: incomplete access key response")
	}
	refBytes, err := json.Marshal(awsHoneyRef{AccountID: b.accountID, DecoyID: decoyID, UserName: user, AccessKeyID: key.Result.AccessKey.ID, OwnerTag: b.ownerTag})
	if err != nil {
		_ = b.deleteOwnedUser(ctx, user)
		return "", nil, err
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- one-time decoy reveal; caller seals or writes and wipes this []byte (CWE-200)
		AccessKeyID     string           `json:"access_key_id"`
		SecretAccessKey secret.JSONBytes `json:"secret_access_key"`
	}{key.Result.AccessKey.ID, key.Result.AccessKey.Secret})
	if err != nil {
		_ = b.deleteOwnedUser(ctx, user)
		return "", nil, err
	}
	return string(refBytes), credential, nil
}

func (b *AWSHoneyBackend) expectedUserARN(arn, user string) bool {
	for _, partition := range []string{"aws", "aws-us-gov", "aws-cn"} {
		if arn == "arn:"+partition+":iam::"+b.accountID+":user"+awsHoneyPath+user {
			return true
		}
	}
	return false
}

// IAM read APIs may briefly lag a successful write. The access key is never
// minted until ownership and the exact deny policy have both been read back.
func (b *AWSHoneyBackend) waitForIAMReadback(ctx context.Context, subject string, inspect func() (bool, error)) error {
	var last error
	for attempt := 0; attempt < 8; attempt++ {
		ready, err := inspect()
		if err == nil && ready {
			return nil
		}
		if err != nil {
			last = err
		} else {
			last = errors.New("not yet visible")
		}
		if attempt == 7 {
			break
		}
		wait := min(100*time.Millisecond<<attempt, 2*time.Second)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("aws honeytoken: %s readback canceled: %w", subject, ctx.Err())
		case <-timer.C:
		}
	}
	return fmt.Errorf("aws honeytoken: %s readback failed before access-key creation: %w", subject, last)
}

func (b *AWSHoneyBackend) getOwnedUser(ctx context.Context, user string) (bool, error) {
	raw, err := b.query.call(ctx, map[string]string{"Action": "GetUser", "Version": "2010-05-08", "UserName": user})
	if errors.Is(err, errAWSIAMMissing) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("aws honeytoken: inspect IAM user: %w", err)
	}
	var result struct {
		Result struct {
			User struct {
				ARN string `xml:"Arn"`
			} `xml:"User"`
		} `xml:"GetUserResult"`
	}
	decodeErr := xml.Unmarshal(raw, &result)
	secret.Wipe(raw)
	if decodeErr != nil || !b.expectedUserARN(result.Result.User.ARN, user) {
		return false, errors.New("aws honeytoken: colliding IAM user is outside the configured account or path")
	}
	raw, err = b.query.call(ctx, map[string]string{"Action": "ListUserTags", "Version": "2010-05-08", "UserName": user})
	if err != nil {
		return false, fmt.Errorf("aws honeytoken: inspect IAM ownership tag: %w", err)
	}
	var tags struct {
		Result struct {
			Tags []struct {
				Key   string `xml:"Key"`
				Value string `xml:"Value"`
			} `xml:"Tags>member"`
		} `xml:"ListUserTagsResult"`
	}
	decodeErr = xml.Unmarshal(raw, &tags)
	secret.Wipe(raw)
	if decodeErr != nil {
		return false, fmt.Errorf("aws honeytoken: decode IAM ownership tag: %w", decodeErr)
	}
	for _, tag := range tags.Result.Tags {
		if tag.Key == awsHoneyTagName && tag.Value == b.ownerTag {
			return true, nil
		}
	}
	return false, errors.New("aws honeytoken: colliding IAM user lacks this decoy's ownership tag")
}

func (b *AWSHoneyBackend) verifyDenyAll(ctx context.Context, user string) error {
	raw, err := b.query.call(ctx, map[string]string{"Action": "GetUserPolicy", "Version": "2010-05-08", "UserName": user, "PolicyName": awsHoneyPolicyName})
	if err != nil {
		return fmt.Errorf("aws honeytoken: deny-all policy readback: %w", err)
	}
	var result struct {
		Result struct {
			Document string `xml:"PolicyDocument"`
		} `xml:"GetUserPolicyResult"`
	}
	decodeErr := xml.Unmarshal(raw, &result)
	secret.Wipe(raw)
	if decodeErr != nil {
		return fmt.Errorf("aws honeytoken: decode deny-all policy: %w", decodeErr)
	}
	decoded, err := url.QueryUnescape(result.Result.Document)
	if err != nil {
		return fmt.Errorf("aws honeytoken: decode policy document: %w", err)
	}
	var actual, expected any
	if json.Unmarshal([]byte(decoded), &actual) != nil || json.Unmarshal([]byte(awsHoneyDenyAll), &expected) != nil || !reflect.DeepEqual(actual, expected) {
		return errors.New("aws honeytoken: IAM deny-all policy readback differs; access key was not created")
	}
	return nil
}

// Retire removes the key, explicit deny policy, and owned user. Completion is
// reported only after an independent GetUser absence check.
func (b *AWSHoneyBackend) Retire(ctx context.Context, ref string) error {
	var item awsHoneyRef
	if json.Unmarshal([]byte(ref), &item) != nil || item.AccountID != b.accountID || item.OwnerTag != b.ownerTag || item.DecoyID == "" || item.UserName == "" || item.AccessKeyID == "" {
		return errors.New("aws honeytoken: invalid or foreign decoy reference")
	}
	expectedUser, err := scopedNameForRequest(b.query.usernamePrefix, GenerateRequest{LeaseID: item.DecoyID, Role: "honeytoken"}, 64, "_")
	if err != nil || item.UserName != expectedUser {
		return errors.New("aws honeytoken: decoy reference does not match its generated IAM username")
	}
	owned, err := b.getOwnedUser(ctx, item.UserName)
	if err != nil || !owned {
		return err
	}
	if err := b.deleteOwnedUser(ctx, item.UserName); err != nil {
		return err
	}
	owned, err = b.getOwnedUser(ctx, item.UserName)
	if err != nil {
		return err
	}
	if owned {
		return errors.New("aws honeytoken: IAM user still exists after retirement")
	}
	return nil
}

// AWSHoneyReference exposes only non-secret IAM identity metadata. The caller
// must recompute OwnerTag from its tenant/provider/lease before using the ref.
func AWSHoneyReference(ref string) (accountID, decoyID, accessKeyID, ownerTag string, ok bool) {
	var item awsHoneyRef
	if json.Unmarshal([]byte(ref), &item) != nil || !awsAccountID.MatchString(item.AccountID) || item.DecoyID == "" || item.UserName == "" || item.AccessKeyID == "" || item.OwnerTag == "" {
		return "", "", "", "", false
	}
	return item.AccountID, item.DecoyID, item.AccessKeyID, item.OwnerTag, true
}

func (b *AWSHoneyBackend) deleteOwnedUser(ctx context.Context, user string) error {
	raw, err := b.query.call(ctx, map[string]string{"Action": "ListAccessKeys", "Version": "2010-05-08", "UserName": user})
	if err != nil && !errors.Is(err, errAWSIAMMissing) {
		return fmt.Errorf("aws honeytoken: list keys for cleanup: %w", err)
	}
	var listed struct {
		Result struct {
			Keys []struct {
				ID string `xml:"AccessKeyId"`
			} `xml:"AccessKeyMetadata>member"`
		} `xml:"ListAccessKeysResult"`
	}
	if err == nil {
		decodeErr := xml.Unmarshal(raw, &listed)
		secret.Wipe(raw)
		if decodeErr != nil {
			return fmt.Errorf("aws honeytoken: decode key list: %w", decodeErr)
		}
	}
	for _, key := range listed.Result.Keys {
		if key.ID == "" {
			continue
		}
		if _, err := b.query.call(ctx, map[string]string{"Action": "DeleteAccessKey", "Version": "2010-05-08", "UserName": user, "AccessKeyId": key.ID}); err != nil && !errors.Is(err, errAWSIAMMissing) {
			return fmt.Errorf("aws honeytoken: delete access key: %w", err)
		}
	}
	if _, err := b.query.call(ctx, map[string]string{"Action": "DeleteUserPolicy", "Version": "2010-05-08", "UserName": user, "PolicyName": awsHoneyPolicyName}); err != nil && !errors.Is(err, errAWSIAMMissing) {
		return fmt.Errorf("aws honeytoken: delete deny policy: %w", err)
	}
	if _, err := b.query.call(ctx, map[string]string{"Action": "DeleteUser", "Version": "2010-05-08", "UserName": user}); err != nil && !errors.Is(err, errAWSIAMMissing) {
		return fmt.Errorf("aws honeytoken: delete IAM user: %w", err)
	}
	return nil
}
