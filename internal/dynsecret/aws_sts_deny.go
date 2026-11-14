// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// How a revocation ended a provider credential, for the providers that say
// (N3; GitHub App and OAuth tokens, OD-5). An empty method means the provider
// removed the credential itself.
const (
	// RevocationMethodDenyPolicy: a policy the provider enforces denies every
	// request the credential makes, before its native expiry (an AWS STS
	// session denied by an inline policy on its role).
	RevocationMethodDenyPolicy = "deny_policy"
	// RevocationMethodNativeExpiry: nothing ended the credential early; it
	// lapsed at its own expiry.
	RevocationMethodNativeExpiry = "native_expiry"
	// RevocationMethodTokenRevoked: the provider confirmed the token ended
	// when it was presented (GitHub's DELETE /installation/token, or an
	// RFC 7009 revocation endpoint), before its native expiry (OD-5).
	RevocationMethodTokenRevoked = "token_revoked"
)

// MethodRevoker revokes like Provider.Revoke and also names how the credential
// ended.
type MethodRevoker interface {
	RevokeMethod(ctx context.Context, ref string) (string, error)
}

// N3: early revocation of an AWS STS session. STS has no per-session delete,
// but IAM evaluates an explicit Deny in the role's own policies for every
// request a session of the role makes, and aws:userid of an assumed-role
// session is its AssumedRoleId (role ID ":" session name), which names exactly
// one lease's session. Each revoked session gets its own inline policy, so two
// revocations of one role never rewrite a shared document, and the session's
// expiry is in the policy's name, so expired denials are pruned from a listing
// without reading each document.
const (
	awsSTSDenyPolicyPrefix = "trstctl-revoked-"
	// awsSTSDenyClockMargin keeps a denial past the session's expiry by this
	// much, so a clock ahead of AWS's can't prune it while AWS still accepts
	// the session.
	awsSTSDenyClockMargin = 5 * time.Minute
	awsIAMVersion         = "2010-05-08"
)

// AWSSTSDenyPolicyName names the inline role policy that denies one session.
func AWSSTSDenyPolicyName(assumedRoleID string, expiration time.Time) string {
	return awsSTSDenyPolicyPrefix + strconv.FormatInt(expiration.Unix(), 10) + "-" + crypto.SHA256Hex([]byte(assumedRoleID))[:12]
}

// awsSTSDenyPolicyExpiry reads the session expiry from a denial's policy name;
// ok is false for any other policy.
func awsSTSDenyPolicyExpiry(name string) (time.Time, bool) {
	rest, ok := strings.CutPrefix(name, awsSTSDenyPolicyPrefix)
	if !ok {
		return time.Time{}, false
	}
	unix, digest, ok := strings.Cut(rest, "-")
	if !ok || len(digest) != 12 {
		return time.Time{}, false
	}
	seconds, err := strconv.ParseInt(unix, 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0).UTC(), true
}

type awsDenyStatement struct {
	Sid       string                       `json:"Sid"`
	Effect    string                       `json:"Effect"`
	Action    string                       `json:"Action"`
	Resource  string                       `json:"Resource"`
	Condition map[string]map[string]string `json:"Condition"`
}

// awsSTSDenyPolicyDocument denies every action on every resource to the one
// session whose aws:userid is assumedRoleID.
func awsSTSDenyPolicyDocument(assumedRoleID string) (string, error) {
	doc, err := json.Marshal(struct {
		Version   string             `json:"Version"`
		Statement []awsDenyStatement `json:"Statement"`
	}{"2012-10-17", []awsDenyStatement{{
		Sid: "TrstctlRevokedSession", Effect: "Deny", Action: "*", Resource: "*",
		Condition: map[string]map[string]string{"StringEquals": {"aws:userid": assumedRoleID}},
	}}})
	return string(doc), err
}

// RevokeMethod ends the lease's session. Without revoke_with_deny_policy the
// session lapses at its native expiry (ErrAWSSTSSessionActive until then).
// With it, a session that is not past its expiry gets its own inline deny
// policy on the role, read back before the revocation counts, and the role's
// denials of expired sessions are pruned.
func (b *AWSSTSBackend) RevokeMethod(ctx context.Context, ref string) (string, error) {
	now := b.query.now().UTC()
	if !b.denyPolicy {
		if err := CheckAWSSTSExpiration(ref, now); err != nil {
			return "", err
		}
		return RevocationMethodNativeExpiry, nil
	}
	var issued awsSTSRef
	if _, ok := AWSSTSExpiration(ref); !ok || json.Unmarshal([]byte(ref), &issued) != nil {
		return "", errors.New("dynsecret aws-sts: invalid session reference")
	}
	roleName, ok := awsRoleNameFromARN(issued.RoleARN)
	if !ok {
		return "", fmt.Errorf("dynsecret aws-sts: %q is not an IAM role ARN", issued.RoleARN)
	}
	b.pruneDenyPolicies(ctx, roleName, now)
	if !now.Before(issued.Expiration.Add(awsSTSDenyClockMargin)) {
		return RevocationMethodNativeExpiry, nil
	}
	name := AWSSTSDenyPolicyName(issued.AssumedRoleID, issued.Expiration)
	doc, err := awsSTSDenyPolicyDocument(issued.AssumedRoleID)
	if err != nil {
		return "", err
	}
	if _, err := b.denyClient().call(ctx, map[string]string{
		"Action": "PutRolePolicy", "Version": awsIAMVersion, "RoleName": roleName,
		"PolicyName": name, "PolicyDocument": doc,
	}); err != nil {
		return "", fmt.Errorf("dynsecret aws-sts: write the session's deny policy on role %s: %w", roleName, err)
	}
	raw, err := b.denyClient().call(ctx, map[string]string{
		"Action": "GetRolePolicy", "Version": awsIAMVersion, "RoleName": roleName, "PolicyName": name,
	})
	if err != nil {
		return "", fmt.Errorf("dynsecret aws-sts: read back the session's deny policy on role %s: %w", roleName, err)
	}
	if !awsSTSDenyPolicyHolds(raw, issued.AssumedRoleID) {
		return "", fmt.Errorf("dynsecret aws-sts: role %s's policy %s read back without the session's denial", roleName, name)
	}
	return RevocationMethodDenyPolicy, nil
}

// pruneDenyPolicies deletes the role's denials of sessions past their expiry
// (and the clock margin). It is best effort: what it leaves, the next
// revocation of the role prunes.
func (b *AWSSTSBackend) pruneDenyPolicies(ctx context.Context, roleName string, now time.Time) {
	var expired []string
	for marker, pages := "", 0; pages < 20; pages++ {
		params := map[string]string{"Action": "ListRolePolicies", "Version": awsIAMVersion, "RoleName": roleName, "MaxItems": "100"}
		if marker != "" {
			params["Marker"] = marker
		}
		raw, err := b.denyClient().call(ctx, params)
		if err != nil {
			return
		}
		var page struct {
			Result struct {
				Names       []string `xml:"PolicyNames>member"`
				IsTruncated bool     `xml:"IsTruncated"`
				Marker      string   `xml:"Marker"`
			} `xml:"ListRolePoliciesResult"`
		}
		if xml.Unmarshal(raw, &page) != nil {
			return
		}
		for _, name := range page.Result.Names {
			if expiry, ok := awsSTSDenyPolicyExpiry(name); ok && !now.Before(expiry.Add(awsSTSDenyClockMargin)) {
				expired = append(expired, name)
			}
		}
		if !page.Result.IsTruncated || page.Result.Marker == "" {
			break
		}
		marker = page.Result.Marker
	}
	for _, name := range expired {
		if _, err := b.denyClient().call(ctx, map[string]string{
			"Action": "DeleteRolePolicy", "Version": awsIAMVersion, "RoleName": roleName, "PolicyName": name,
		}); err != nil && !errors.Is(err, errAWSIAMMissing) {
			return
		}
	}
}

// awsSTSDenyPolicyHolds reports whether a GetRolePolicy answer holds a
// statement that denies every action on every resource to exactly the session
// assumedRoleID. IAM returns the document URL-encoded (RFC 3986); a document
// that is already JSON is read as it is.
func awsSTSDenyPolicyHolds(raw []byte, assumedRoleID string) bool {
	var answer struct {
		Result struct {
			Document string `xml:"PolicyDocument"`
		} `xml:"GetRolePolicyResult"`
	}
	if xml.Unmarshal(raw, &answer) != nil {
		return false
	}
	doc := strings.TrimSpace(answer.Result.Document)
	if !json.Valid([]byte(doc)) {
		decoded, err := url.PathUnescape(doc)
		if err != nil || !json.Valid([]byte(decoded)) {
			return false
		}
		doc = decoded
	}
	var policy struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal([]byte(doc), &policy) != nil {
		return false
	}
	var statements []json.RawMessage
	if json.Unmarshal(policy.Statement, &statements) != nil {
		statements = []json.RawMessage{policy.Statement}
	}
	for _, rawStatement := range statements {
		var s struct {
			Effect    string                                `json:"Effect"`
			Action    json.RawMessage                       `json:"Action"`
			Resource  json.RawMessage                       `json:"Resource"`
			Condition map[string]map[string]json.RawMessage `json:"Condition"`
		}
		if json.Unmarshal(rawStatement, &s) != nil || s.Effect != "Deny" ||
			!awsPolicyValuesAre(s.Action, "*") || !awsPolicyValuesAre(s.Resource, "*") || len(s.Condition) != 1 {
			continue
		}
		for operator, keys := range s.Condition {
			if operator != "StringEquals" || len(keys) != 1 {
				continue
			}
			for key, values := range keys {
				if strings.EqualFold(key, "aws:userid") && awsPolicyValuesAre(values, assumedRoleID) {
					return true
				}
			}
		}
	}
	return false
}

// awsPolicyValuesAre reports whether a policy element (a string or a list of
// strings) is exactly the one value want.
func awsPolicyValuesAre(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var list []string
	return json.Unmarshal(raw, &list) == nil && len(list) == 1 && list[0] == want
}

// denyClient signs the denials: the denial credential when one is set
// (N3-L1), else the issuing credential.
func (b *AWSSTSBackend) denyClient() *AWSIAMBackend {
	if b.deny != nil {
		return b.deny
	}
	return b.iam
}
