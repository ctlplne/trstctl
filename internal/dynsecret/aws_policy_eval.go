// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/cloudhttp"
)

// G2-L1: an STS lease's role is read statement by statement. Each attached
// managed policy's default version and each inline policy's document is read
// from IAM and every statement is rendered as what it allows or denies, on
// what, under which condition keys; then the statements are weighed together
// the way IAM decides a request — an explicit deny wins over any allow — so
// the graph says when a role is a full administrator and when an allow is
// overridden by a deny. Permission boundaries, session policies, service
// control policies and resource policies are not read.

// maxPolicyDocuments bounds the documents one lease's access reads.
const maxPolicyDocuments = 40

// maxPolicyDocumentBytes bounds one decoded policy document; IAM's own limit
// is far smaller.
const maxPolicyDocumentBytes = 128 << 10

// maxPolicyListed bounds the actions or resources one statement lists.
const maxPolicyListed = 10

// awsPolicyRef names one policy of the role.
type awsPolicyRef struct {
	label string // "managed policy NAME" or "inline policy NAME"
	arn   string // managed only
	name  string // inline only
}

// awsStringList is an IAM policy element that is one string or a list.
type awsStringList []string

func (l *awsStringList) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '"' {
		var one string
		if err := json.Unmarshal(raw, &one); err != nil {
			return err
		}
		*l = awsStringList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return err
	}
	*l = many
	return nil
}

type awsPolicyStatement struct {
	Effect      string                                `json:"Effect"`
	Action      awsStringList                         `json:"Action"`
	NotAction   awsStringList                         `json:"NotAction"`
	Resource    awsStringList                         `json:"Resource"`
	NotResource awsStringList                         `json:"NotResource"`
	Condition   map[string]map[string]json.RawMessage `json:"Condition"`
}

// policyStatement is one statement with the policy it came from.
type policyStatement struct {
	label string
	awsPolicyStatement
}

// parseAWSPolicyDocument decodes a URL-encoded policy document's statements.
func parseAWSPolicyDocument(encoded string) ([]awsPolicyStatement, error) {
	doc, err := url.QueryUnescape(strings.TrimSpace(encoded))
	if err != nil || len(doc) == 0 || len(doc) > maxPolicyDocumentBytes {
		return nil, errors.New("dynsecret: unreadable policy document")
	}
	var body struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &body); err != nil {
		return nil, errors.New("dynsecret: unreadable policy document")
	}
	raw := bytes.TrimSpace(body.Statement)
	var out []awsPolicyStatement
	switch {
	case len(raw) > 0 && raw[0] == '[':
		err = json.Unmarshal(raw, &out)
	case len(raw) > 0 && raw[0] == '{':
		var one awsPolicyStatement
		err = json.Unmarshal(raw, &one)
		out = []awsPolicyStatement{one}
	default:
		err = errors.New("no statement")
	}
	if err != nil {
		return nil, errors.New("dynsecret: unreadable policy statements")
	}
	for _, s := range out {
		if s.Effect != "Allow" && s.Effect != "Deny" {
			return nil, errors.New("dynsecret: a policy statement's effect is neither Allow nor Deny")
		}
	}
	return out, nil
}

// listed renders a sorted, bounded list.
func listed(values []string) string {
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	if len(sorted) > maxPolicyListed {
		return strings.Join(sorted[:maxPolicyListed], ", ") + " and " + strconv.Itoa(len(sorted)-maxPolicyListed) + " more"
	}
	return strings.Join(sorted, ", ")
}

// conditionKeys lists a statement's condition keys as "operator key".
func conditionKeys(c map[string]map[string]json.RawMessage) []string {
	var keys []string
	for op, entries := range c {
		for key := range entries {
			keys = append(keys, op+" "+key)
		}
	}
	slices.Sort(keys)
	return keys
}

// statementGrant renders one statement.
func statementGrant(s policyStatement) string {
	actions := "no action"
	switch {
	case len(s.NotAction) > 0:
		actions = "every action except " + listed(s.NotAction)
	case slices.Contains(s.Action, "*"):
		actions = "every action"
	case len(s.Action) > 0:
		actions = listed(s.Action)
	}
	resources := "no resource"
	switch {
	case len(s.NotResource) > 0:
		resources = "every resource except " + listed(s.NotResource)
	case slices.Contains(s.Resource, "*"):
		resources = "every resource"
	case len(s.Resource) > 0:
		resources = listed(s.Resource)
	}
	out := s.label + ": " + strings.ToLower(s.Effect) + " " + actions + " on " + resources
	if keys := conditionKeys(s.Condition); len(keys) > 0 {
		out += " when " + listed(keys)
	}
	return out
}

// actionCovered reports whether an IAM action pattern covers action
// (case-insensitively, with * and ? wildcards).
func actionCovered(pattern, action string) bool {
	ok, err := path.Match(strings.ToLower(pattern), strings.ToLower(action))
	return err == nil && ok
}

// weighStatements is the IAM decision applied across the role's statements:
// an unconditional allow of every action on every resource makes the role a
// full administrator unless a deny narrows it, and an allow every one of
// whose actions an unconditional deny on every resource covers is overridden.
func weighStatements(statements []policyStatement) []string {
	var denies []policyStatement
	for _, s := range statements {
		if s.Effect == "Deny" {
			denies = append(denies, s)
		}
	}
	var out []string
	for _, s := range statements {
		if s.Effect != "Allow" || len(s.NotAction) > 0 {
			continue
		}
		if slices.Contains(s.Action, "*") && slices.Contains(s.Resource, "*") && len(s.Condition) == 0 {
			if len(denies) == 0 {
				out = append(out, "effective: full administrator ("+s.label+" allows every action on every resource with no condition, and no statement denies)")
			} else {
				out = append(out, "effective: every action on every resource ("+s.label+") except what the deny statements name")
			}
			continue
		}
		for _, d := range denies {
			if len(d.Condition) > 0 || len(d.NotAction) > 0 || !slices.Contains(d.Resource, "*") || len(s.Action) == 0 {
				continue
			}
			covered := true
			for _, a := range s.Action {
				hit := false
				for _, p := range d.Action {
					if actionCovered(p, a) {
						hit = true
						break
					}
				}
				covered = covered && hit
			}
			if covered {
				out = append(out, "effective: "+s.label+"'s allow of "+listed(s.Action)+" is overridden by "+d.label+"'s deny")
				break
			}
		}
	}
	return out
}

// readPolicyStatements reads each policy's document and returns the grants
// its statements and their weighing add. A document IAM refuses or a policy
// gone between the listing and the read is named, not fatal; IAM out of
// reach is.
func (b *AWSSTSBackend) readPolicyStatements(ctx context.Context, roleName string, policies []awsPolicyRef) ([]string, error) {
	var grants []string
	var statements []policyStatement
	for i, p := range policies {
		if i == maxPolicyDocuments {
			grants = append(grants, fmt.Sprintf("statements not read for %d more policies (past the bound)", len(policies)-i))
			break
		}
		document, err := b.policyDocument(ctx, roleName, p)
		if err != nil {
			var status *cloudhttp.StatusError
			if errors.As(err, &status) && status.StatusCode < 500 {
				grants = append(grants, p.label+": statements unreadable ("+AccessReason(awsAccessError(err))+")")
				continue
			}
			if errors.Is(err, errAWSIAMMissing) {
				grants = append(grants, p.label+": statements unreadable (removed while being read)")
				continue
			}
			return nil, awsAccessError(err)
		}
		parsed, err := parseAWSPolicyDocument(document)
		if err != nil {
			grants = append(grants, p.label+": statements unreadable (unreadable)")
			continue
		}
		for _, s := range parsed {
			st := policyStatement{label: p.label, awsPolicyStatement: s}
			statements = append(statements, st)
			grants = append(grants, statementGrant(st))
		}
	}
	return append(grants, weighStatements(statements)...), nil
}

// policyDocument reads one policy's URL-encoded document: a managed policy's
// default version, or an inline policy of the role.
func (b *AWSSTSBackend) policyDocument(ctx context.Context, roleName string, p awsPolicyRef) (string, error) {
	if p.arn == "" {
		raw, err := b.iam.call(ctx, map[string]string{"Action": "GetRolePolicy", "Version": "2010-05-08", "RoleName": roleName, "PolicyName": p.name})
		if err != nil {
			return "", err
		}
		var out struct {
			Document string `xml:"GetRolePolicyResult>PolicyDocument"`
		}
		if err := xml.Unmarshal(raw, &out); err != nil {
			return "", ErrAccessUnreadable
		}
		return out.Document, nil
	}
	raw, err := b.iam.call(ctx, map[string]string{"Action": "GetPolicy", "Version": "2010-05-08", "PolicyArn": p.arn})
	if err != nil {
		return "", err
	}
	var policy struct {
		Version string `xml:"GetPolicyResult>Policy>DefaultVersionId"`
	}
	if err := xml.Unmarshal(raw, &policy); err != nil || policy.Version == "" {
		return "", ErrAccessUnreadable
	}
	raw, err = b.iam.call(ctx, map[string]string{"Action": "GetPolicyVersion", "Version": "2010-05-08", "PolicyArn": p.arn, "VersionId": policy.Version})
	if err != nil {
		return "", err
	}
	var version struct {
		Document string `xml:"GetPolicyVersionResult>PolicyVersion>Document"`
	}
	if err := xml.Unmarshal(raw, &version); err != nil {
		return "", ErrAccessUnreadable
	}
	return version.Document, nil
}
