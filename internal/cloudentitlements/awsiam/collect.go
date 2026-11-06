// SPDX-License-Identifier: BUSL-1.1
package awsiam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/crypto"
)

// Collect reads only operator-selected machine users/roles. Any failed read
// leaves that identity uncaptured; it never marks partial policy sets complete.
func (c *Client) Collect(ctx context.Context, selections []Selection) (Capture, error) {
	capture := Capture{CollectedAt: c.cfg.Now().UTC()}
	if len(selections) == 0 || len(selections) > MaxPrincipals {
		return capture, errors.New("awsiam: select between 1 and 256 workload identities")
	}
	seen := map[Selection]bool{}
	for _, s := range selections {
		if (s.Kind != awspolicy.IAMUser && s.Kind != awspolicy.IAMRole) || !validateName(s.Name) || seen[s] {
			return capture, errors.New("awsiam: invalid or duplicate workload identity selection")
		}
		seen[s] = true
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	session := &captureSession{c: c}
	for _, selection := range selections {
		identity, err := session.identity(ctx, selection)
		capture.Calls = session.calls
		if err != nil {
			return capture, fmt.Errorf("awsiam: selected %s %s capture failed: %w", selection.Kind, selection.Name, err)
		}
		capture.Identities = append(capture.Identities, identity)
	}
	return capture, nil
}
func (s *captureSession) identity(ctx context.Context, selection Selection) (Identity, error) {
	out := Identity{Name: selection.Name, Evidence: awspolicy.Evidence{Identity: awspolicy.PolicySet{Coverage: awspolicy.Complete}, Boundary: awspolicy.PolicySet{Coverage: awspolicy.Absent}, Session: awspolicy.PolicySet{Coverage: awspolicy.Absent}, Resource: awspolicy.PolicySet{Coverage: awspolicy.Unavailable}, SCPCoverage: awspolicy.Unavailable, RCPCoverage: awspolicy.Unavailable}, Gaps: []string{"resource policies unavailable", "organization SCP hierarchy unavailable", "organization RCP hierarchy unavailable", "API activity log coverage unavailable"}}
	typ := "User"
	if selection.Kind == awspolicy.IAMRole {
		typ = "Role"
	}
	response, err := s.call(ctx, "Get"+typ, url.Values{typ + "Name": {selection.Name}})
	if err != nil {
		return out, err
	}
	native, err := response.child(typ)
	if err != nil {
		return out, err
	}
	name, err := native.value(typ + "Name")
	if err != nil || name != selection.Name {
		return out, errors.New("returned identity name differs from selection")
	}
	arn, err := native.value("Arn")
	if err != nil {
		return out, err
	}
	parts := strings.SplitN(arn, ":", 6)
	if len(arn) > 2048 || len(parts) != 6 || parts[0] != "arn" || (parts[1] != "aws" && parts[1] != "aws-us-gov" && parts[1] != "aws-cn") || parts[2] != "iam" || parts[3] != "" || !account(parts[4]) || !strings.HasPrefix(parts[5], strings.ToLower(typ)+"/") || !strings.HasSuffix(parts[5], "/"+selection.Name) {
		return out, errors.New("returned IAM identity ARN is invalid or differs from selection")
	}
	out.Principal = awspolicy.Principal{Kind: selection.Kind, ARN: arn, AccountID: parts[4]}
	created, err := native.value("CreateDate")
	if err != nil {
		return out, err
	}
	out.Created, err = parseDate(created)
	if err != nil {
		return out, err
	}
	if typ == "Role" {
		trust, err := native.value("AssumeRolePolicyDocument")
		if err != nil {
			return out, err
		}
		out.TrustDocument, err = decodePolicy(trust)
		if err != nil {
			return out, err
		}
		if err = s.retainPolicy(out.TrustDocument); err != nil {
			return out, err
		}
		last, err := native.optional("RoleLastUsed")
		if err != nil {
			return out, err
		}
		if last != nil {
			value, err := last.optionalValue("LastUsedDate")
			if err != nil {
				return out, err
			}
			if value != "" {
				at, err := parseDate(value)
				if err != nil {
					return out, err
				}
				out.LastUsed = &at
			}
		}
	}
	if err = s.policies(ctx, typ, selection.Name, &out); err != nil {
		return out, err
	}
	boundary, err := native.optional("PermissionsBoundary")
	if err != nil {
		return out, err
	}
	if boundary != nil {
		arn, err := boundary.value("PermissionsBoundaryArn")
		if err != nil {
			return out, err
		}
		if err = s.managed(ctx, arn, "boundary", &out); err != nil {
			return out, err
		}
		out.Evidence.Boundary.Coverage = awspolicy.Complete
	}
	if typ == "User" {
		groups, err := s.list(ctx, "ListGroupsForUser", url.Values{"UserName": {selection.Name}}, "Groups")
		if err != nil {
			return out, err
		}
		if len(groups) > 128 {
			return out, errors.New("group count exceeds bound")
		}
		names := map[string]bool{}
		for _, group := range groups {
			name, err := group.value("GroupName")
			if err != nil || !validateName(name) || names[name] {
				return out, errors.New("invalid or duplicate group name")
			}
			names[name] = true
			if err = s.policies(ctx, "Group", name, &out); err != nil {
				return out, err
			}
		}
		if err = s.keys(ctx, selection.Name, &out); err != nil {
			return out, err
		}
	}
	return out, nil
}
func account(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
func parseDate(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() {
		return time.Time{}, errors.New("invalid native IAM timestamp")
	}
	return parsed.UTC(), nil
}
func decodePolicy(value string) ([]byte, error) {
	if len(value) == 0 || len(value) > 3*(64<<10) {
		return nil, errors.New("policy document exceeds bound")
	}
	if !strings.HasPrefix(strings.TrimSpace(value), "{") {
		decoded, err := url.PathUnescape(value)
		if err != nil {
			return nil, errors.New("invalid policy URL encoding")
		}
		value = decoded
	}
	raw := []byte(value)
	if len(raw) > 64<<10 || !json.Valid(raw) {
		return nil, errors.New("invalid bounded policy JSON")
	}
	return raw, nil
}
func (s *captureSession) list(ctx context.Context, action string, params url.Values, container string) ([]*element, error) {
	var members []*element
	seen := map[string]bool{}
	for pages := 0; pages < 100; pages++ {
		result, err := s.call(ctx, action, params)
		if err != nil {
			return nil, err
		}
		list, err := result.child(container)
		if err != nil {
			return nil, err
		}
		for _, item := range list.children {
			if item.name != "member" {
				return nil, errors.New("invalid IAM list member")
			}
			members = append(members, item)
			if len(members) > 2048 {
				return nil, errors.New("IAM list exceeds member bound")
			}
		}
		truncated, err := result.value("IsTruncated")
		if err != nil {
			return nil, err
		}
		if truncated == "false" {
			return members, nil
		}
		if truncated != "true" {
			return nil, errors.New("invalid IAM pagination flag")
		}
		marker, err := result.value("Marker")
		if err != nil || len(marker) == 0 || len(marker) > 2048 || seen[marker] {
			return nil, errors.New("missing or repeated IAM pagination marker")
		}
		seen[marker] = true
		params.Set("Marker", marker)
	}
	return nil, errors.New("IAM pagination exceeds page bound")
}
func (s *captureSession) policies(ctx context.Context, typ, name string, out *Identity) error {
	params := url.Values{typ + "Name": {name}}
	inline, err := s.list(ctx, "List"+typ+"Policies", params, "PolicyNames")
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, item := range inline {
		policyName := item.text.String()
		if len(item.children) > 0 || !validateName(policyName) || seen[policyName] {
			return errors.New("invalid or duplicate IAM policy name")
		}
		seen[policyName] = true
		result, err := s.call(ctx, "Get"+typ+"Policy", url.Values{typ + "Name": {name}, "PolicyName": {policyName}})
		if err != nil {
			return err
		}
		encoded, err := result.value("PolicyDocument")
		if err != nil {
			return err
		}
		raw, err := decodePolicy(encoded)
		if err != nil {
			return err
		}
		if err = s.addPolicy(out, "identity", typ+":"+name+":"+policyName, "", raw); err != nil {
			return err
		}
	}
	attached, err := s.list(ctx, "ListAttached"+typ+"Policies", url.Values{typ + "Name": {name}}, "AttachedPolicies")
	if err != nil {
		return err
	}
	for _, item := range attached {
		arn, err := item.value("PolicyArn")
		if err != nil {
			return err
		}
		if err = s.managed(ctx, arn, "identity", out); err != nil {
			return err
		}
	}
	return nil
}
func (s *captureSession) managed(ctx context.Context, arn, category string, out *Identity) error {
	parts := strings.SplitN(arn, ":", 6)
	if len(arn) > 2048 || len(parts) != 6 || parts[0] != "arn" || parts[2] != "iam" || parts[3] != "" || !strings.HasPrefix(parts[5], "policy/") || (parts[4] != out.Principal.AccountID && parts[4] != "aws") {
		return errors.New("invalid attached policy ARN")
	}
	for _, receipt := range out.PolicyReceipts {
		if receipt.Category == category && receipt.ID == arn {
			return nil
		}
	}
	response, err := s.call(ctx, "GetPolicy", url.Values{"PolicyArn": {arn}})
	if err != nil {
		return err
	}
	policy, err := response.child("Policy")
	if err != nil {
		return err
	}
	returned, err := policy.value("Arn")
	if err != nil || returned != arn {
		return errors.New("managed policy ARN readback differs")
	}
	version, err := policy.value("DefaultVersionId")
	if err != nil || !validVersion(version) {
		return errors.New("invalid managed policy version")
	}
	response, err = s.call(ctx, "GetPolicyVersion", url.Values{"PolicyArn": {arn}, "VersionId": {version}})
	if err != nil {
		return err
	}
	policy, err = response.child("PolicyVersion")
	if err != nil {
		return err
	}
	returned, err = policy.value("VersionId")
	if err != nil || returned != version {
		return errors.New("managed policy version readback differs")
	}
	encoded, err := policy.value("Document")
	if err != nil {
		return err
	}
	raw, err := decodePolicy(encoded)
	if err != nil {
		return err
	}
	return s.addPolicy(out, category, arn, version, raw)
}
func validVersion(v string) bool {
	if len(v) < 2 || len(v) > 16 || v[0] != 'v' {
		return false
	}
	for _, r := range v[1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
func (s *captureSession) addPolicy(out *Identity, category, id, version string, raw []byte) error {
	if len(out.PolicyReceipts) >= 64 {
		return errors.New("identity policy capture exceeds bound")
	}
	if err := s.retainPolicy(raw); err != nil {
		return err
	}
	digest := crypto.SHA256Hex(raw)
	parsed, err := awspolicy.Parse(digest, raw)
	if err != nil {
		return fmt.Errorf("unusable captured policy: %w", err)
	}
	receipt := PolicyReceipt{RawDocument: append([]byte(nil), raw...), Category: category, ID: id, Version: version, SHA256: digest, Document: append([]byte(nil), raw...)}
	out.PolicyReceipts = append(out.PolicyReceipts, receipt)
	if category == "boundary" {
		out.Evidence.Boundary.Documents = append(out.Evidence.Boundary.Documents, parsed)
	} else {
		out.Evidence.Identity.Documents = append(out.Evidence.Identity.Documents, parsed)
	}
	return nil
}
func (s *captureSession) keys(ctx context.Context, user string, out *Identity) error {
	keys, err := s.list(ctx, "ListAccessKeys", url.Values{"UserName": {user}}, "AccessKeyMetadata")
	if err != nil {
		return err
	}
	if len(keys) > 2 {
		return errors.New("IAM user key count exceeds native limit")
	}
	seen := map[string]bool{}
	for _, item := range keys {
		nativeUser, err := item.value("UserName")
		if err != nil || nativeUser != user {
			return errors.New("access key user differs")
		}
		id, err := item.value("AccessKeyId")
		if err != nil || !validateName(id) || seen[id] {
			return errors.New("invalid or duplicate access key identifier")
		}
		seen[id] = true
		status, err := item.value("Status")
		if err != nil || (status != "Active" && status != "Inactive") {
			return errors.New("invalid access key status")
		}
		created, err := item.value("CreateDate")
		if err != nil {
			return err
		}
		at, err := parseDate(created)
		if err != nil {
			return err
		}
		key := Key{ID: id, Status: status, Created: at, LastUseCoverage: awspolicy.Complete}
		result, err := s.call(ctx, "GetAccessKeyLastUsed", url.Values{"AccessKeyId": {id}})
		if err != nil {
			return err
		}
		nativeUser, err = result.value("UserName")
		if err != nil || nativeUser != user {
			return errors.New("access key last-use user differs")
		}
		used, err := result.child("AccessKeyLastUsed")
		if err != nil {
			return err
		}
		value, err := used.optionalValue("LastUsedDate")
		if err != nil {
			return err
		}
		if value != "" {
			last, err := parseDate(value)
			if err != nil {
				return err
			}
			key.LastUsed = &last
		}
		key.LastUsedService, err = used.optionalValue("ServiceName")
		if err != nil {
			return err
		}
		key.LastUsedRegion, err = used.optionalValue("Region")
		if err != nil {
			return err
		}
		if len(key.LastUsedService) > 128 || len(key.LastUsedRegion) > 128 {
			return errors.New("key last-use metadata exceeds bound")
		}
		if key.LastUsedService == "N/A" {
			key.LastUsedService = ""
		}
		if key.LastUsedRegion == "N/A" {
			key.LastUsedRegion = ""
		}
		out.Keys = append(out.Keys, key)
	}
	return nil
}

func (s *captureSession) retainPolicy(raw []byte) error {
	if len(raw) > 8<<20-s.policyBytes {
		return errors.New("IAM capture exceeds total retained policy byte bound")
	}
	s.policyBytes += len(raw)
	return nil
}
