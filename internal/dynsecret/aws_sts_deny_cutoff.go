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

// N3-L2: a role's inline policies share IAM's 10,240-character quota, so a
// role whose sessions are revoked often runs out of room for one more
// per-session denial. With DenyBeforeCutoffWhenFull a revocation that meets
// the quota attaches a customer-managed policy (managed policies do not count
// against it) that denies every session of the role issued before now
// (aws:TokenIssueTime), the revoked session with them. Every other session of
// the role issued before the cutoff is denied too, so the fallback is opt-in.
//
// Each cutoff is its own managed policy, never a new version of a shared one:
// two replicas falling back at once attach two policies, and the union of two
// denials is the later cutoff, so a cutoff never moves backwards. Once a
// cutoff is attached and read back, older cutoffs of the role are detached and
// deleted, and the role's per-session denials of sessions that must have been
// issued before it are deleted, which frees the inline quota again.

const (
	awsSTSCutoffPolicyPrefix = "trstctl-cutoff-"
	awsSTSCutoffPolicyPath   = "/trstctl/"
	// awsSTSMinSessionTTL is STS's shortest session: a session expiring by
	// cutoff+15m was issued before the cutoff.
	awsSTSMinSessionTTL = 15 * time.Minute
)

// awsSTSCutoffPolicyName names a role's cutoff policy: the role's digest
// keeps one role's cutoffs apart from another's in the account-wide policy
// namespace, and the cutoff's Unix second orders them.
func awsSTSCutoffPolicyName(roleName string, cutoff time.Time) string {
	return awsSTSCutoffPolicyPrefix + crypto.SHA256Hex([]byte(roleName))[:10] + "-" + strconv.FormatInt(cutoff.Unix(), 10)
}

// awsSTSCutoffFromName reads the cutoff of one of roleName's cutoff policies.
func awsSTSCutoffFromName(roleName, name string) (time.Time, bool) {
	rest, ok := strings.CutPrefix(name, awsSTSCutoffPolicyPrefix+crypto.SHA256Hex([]byte(roleName))[:10]+"-")
	if !ok {
		return time.Time{}, false
	}
	seconds, err := strconv.ParseInt(rest, 10, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0).UTC(), true
}

// awsSTSCutoffPolicyDocument denies every action on every resource to every
// session issued before cutoff.
func awsSTSCutoffPolicyDocument(cutoff time.Time) (string, error) {
	doc, err := json.Marshal(struct {
		Version   string             `json:"Version"`
		Statement []awsDenyStatement `json:"Statement"`
	}{"2012-10-17", []awsDenyStatement{{
		Sid: "TrstctlRevokedBefore", Effect: "Deny", Action: "*", Resource: "*",
		Condition: map[string]map[string]string{"DateLessThan": {"aws:TokenIssueTime": cutoff.UTC().Format(time.RFC3339)}},
	}}})
	return string(doc), err
}

// awsPolicyARNFor is the ARN of a /trstctl/ policy in the role's account and
// partition.
func awsPolicyARNFor(roleARN, name string) (string, bool) {
	parts := strings.SplitN(roleARN, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "iam" || parts[4] == "" {
		return "", false
	}
	return "arn:" + parts[1] + ":iam::" + parts[4] + ":policy" + awsSTSCutoffPolicyPath + name, true
}

// denyBeforeCutoff attaches a cutoff policy at cutoff, reads it back, and
// then removes what it supersedes.
func (b *AWSSTSBackend) denyBeforeCutoff(ctx context.Context, roleName, roleARN string, cutoff time.Time) error {
	cutoff = cutoff.UTC().Truncate(time.Second).Add(time.Second)
	name := awsSTSCutoffPolicyName(roleName, cutoff)
	arn, ok := awsPolicyARNFor(roleARN, name)
	if !ok {
		return fmt.Errorf("%q is not an IAM role ARN", roleARN)
	}
	doc, err := awsSTSCutoffPolicyDocument(cutoff)
	if err != nil {
		return err
	}
	iam := b.denyClient()
	if _, err := iam.call(ctx, map[string]string{
		"Action": "CreatePolicy", "Version": awsIAMVersion, "PolicyName": name, "Path": awsSTSCutoffPolicyPath,
		"PolicyDocument": doc, "Description": "trstctl: denies every session of role " + roleName + " issued before " + cutoff.Format(time.RFC3339),
	}); err != nil && !errors.Is(err, errAWSIAMAlreadyExists) {
		return fmt.Errorf("create the cutoff policy: %w", err)
	}
	if _, err := iam.call(ctx, map[string]string{
		"Action": "AttachRolePolicy", "Version": awsIAMVersion, "RoleName": roleName, "PolicyArn": arn,
	}); err != nil {
		return fmt.Errorf("attach the cutoff policy: %w", err)
	}
	attached, err := b.attachedCutoffPolicies(ctx, roleName)
	if err != nil {
		return fmt.Errorf("read back the role's attached policies: %w", err)
	}
	if _, ok := attached[arn]; !ok {
		return fmt.Errorf("the role does not list the cutoff policy %s as attached", arn)
	}
	if err := b.cutoffPolicyHolds(ctx, arn, cutoff); err != nil {
		return err
	}
	// Best effort from here: what is left, the next fallback removes.
	for other, otherCutoff := range attached {
		if other == arn || !otherCutoff.Before(cutoff) {
			continue
		}
		if _, err := iam.call(ctx, map[string]string{"Action": "DetachRolePolicy", "Version": awsIAMVersion, "RoleName": roleName, "PolicyArn": other}); err != nil && !errors.Is(err, errAWSIAMMissing) {
			continue
		}
		_, _ = iam.call(ctx, map[string]string{"Action": "DeletePolicy", "Version": awsIAMVersion, "PolicyArn": other})
	}
	b.pruneDenialsBefore(ctx, roleName, cutoff)
	return nil
}

// attachedCutoffPolicies lists the role's attached /trstctl/ cutoff policies
// by ARN with their cutoffs.
func (b *AWSSTSBackend) attachedCutoffPolicies(ctx context.Context, roleName string) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	for marker, pages := "", 0; pages < 20; pages++ {
		params := map[string]string{"Action": "ListAttachedRolePolicies", "Version": awsIAMVersion, "RoleName": roleName,
			"PathPrefix": awsSTSCutoffPolicyPath, "MaxItems": "100"}
		if marker != "" {
			params["Marker"] = marker
		}
		raw, err := b.denyClient().call(ctx, params)
		if err != nil {
			return nil, err
		}
		var page struct {
			Result struct {
				Policies []struct {
					Name string `xml:"PolicyName"`
					ARN  string `xml:"PolicyArn"`
				} `xml:"AttachedPolicies>member"`
				IsTruncated bool   `xml:"IsTruncated"`
				Marker      string `xml:"Marker"`
			} `xml:"ListAttachedRolePoliciesResult"`
		}
		if err := xml.Unmarshal(raw, &page); err != nil {
			return nil, err
		}
		for _, p := range page.Result.Policies {
			if cutoff, ok := awsSTSCutoffFromName(roleName, p.Name); ok {
				out[p.ARN] = cutoff
			}
		}
		if !page.Result.IsTruncated || page.Result.Marker == "" {
			return out, nil
		}
		marker = page.Result.Marker
	}
	return out, nil
}

// cutoffPolicyHolds reads the policy's default version back and requires
// exactly the denial of sessions issued before cutoff.
func (b *AWSSTSBackend) cutoffPolicyHolds(ctx context.Context, arn string, cutoff time.Time) error {
	raw, err := b.denyClient().call(ctx, map[string]string{"Action": "GetPolicy", "Version": awsIAMVersion, "PolicyArn": arn})
	if err != nil {
		return fmt.Errorf("read back the cutoff policy: %w", err)
	}
	var policy struct {
		Version string `xml:"GetPolicyResult>Policy>DefaultVersionId"`
	}
	if xml.Unmarshal(raw, &policy) != nil || policy.Version == "" {
		return errors.New("the cutoff policy read back without a default version")
	}
	raw, err = b.denyClient().call(ctx, map[string]string{"Action": "GetPolicyVersion", "Version": awsIAMVersion, "PolicyArn": arn, "VersionId": policy.Version})
	if err != nil {
		return fmt.Errorf("read back the cutoff policy's document: %w", err)
	}
	var version struct {
		Document string `xml:"GetPolicyVersionResult>PolicyVersion>Document"`
	}
	if xml.Unmarshal(raw, &version) != nil {
		return errors.New("the cutoff policy's document could not be read")
	}
	if !awsSTSCutoffHolds(version.Document, cutoff) {
		return fmt.Errorf("the cutoff policy %s read back without the denial of sessions issued before %s", arn, cutoff.Format(time.RFC3339))
	}
	return nil
}

// awsSTSCutoffHolds reports whether a policy document (JSON, or IAM's
// URL-encoded form) denies every action on every resource to sessions issued
// before cutoff.
func awsSTSCutoffHolds(document string, cutoff time.Time) bool {
	doc := strings.TrimSpace(document)
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
	want := cutoff.UTC().Format(time.RFC3339)
	for _, raw := range statements {
		var s struct {
			Effect    string                                `json:"Effect"`
			Action    json.RawMessage                       `json:"Action"`
			Resource  json.RawMessage                       `json:"Resource"`
			Condition map[string]map[string]json.RawMessage `json:"Condition"`
		}
		if json.Unmarshal(raw, &s) != nil || s.Effect != "Deny" || !awsPolicyValuesAre(s.Action, "*") ||
			!awsPolicyValuesAre(s.Resource, "*") || len(s.Condition) != 1 {
			continue
		}
		keys, ok := s.Condition["DateLessThan"]
		if !ok || len(keys) != 1 {
			continue
		}
		for key, values := range keys {
			if strings.EqualFold(key, "aws:TokenIssueTime") && awsPolicyValuesAre(values, want) {
				return true
			}
		}
	}
	return false
}

// pruneDenialsBefore deletes the role's per-session denials of sessions that
// must have been issued before the cutoff — they expire within STS's shortest
// session of it — which the cutoff covers. Best effort.
func (b *AWSSTSBackend) pruneDenialsBefore(ctx context.Context, roleName string, cutoff time.Time) {
	raw, err := b.denyClient().call(ctx, map[string]string{"Action": "ListRolePolicies", "Version": awsIAMVersion, "RoleName": roleName, "MaxItems": "1000"})
	if err != nil {
		return
	}
	var page struct {
		Names []string `xml:"ListRolePoliciesResult>PolicyNames>member"`
	}
	if xml.Unmarshal(raw, &page) != nil {
		return
	}
	for _, name := range page.Names {
		if expiry, ok := awsSTSDenyPolicyExpiry(name); ok && !expiry.After(cutoff.Add(awsSTSMinSessionTTL)) {
			_, _ = b.denyClient().call(ctx, map[string]string{"Action": "DeleteRolePolicy", "Version": awsIAMVersion, "RoleName": roleName, "PolicyName": name})
		}
	}
}
