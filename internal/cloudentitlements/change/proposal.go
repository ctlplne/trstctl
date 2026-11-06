// SPDX-License-Identifier: BUSL-1.1
package change

import (
	"encoding/json"
	"errors"
	"strings"
	"trstctl.com/trstctl/internal/cloudentitlements/assessment"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/crypto"
)

// RestrictivePolicy adds one exact Deny in a separate owned inline policy.
// Existing grants, conditions and denies are never rewritten by this proposal.
func RestrictivePolicy(value assessment.Assessment, index int) ([]byte, string, error) {
	if index < 0 || index >= len(value.Evaluations) {
		return nil, "", errors.New("select a captured permission check")
	}
	item := value.Evaluations[index]
	if !item.Unused || item.Result.Decision != awspolicy.Allowed || item.ActivityCoverage != awspolicy.Complete || !strings.HasPrefix(item.Check.Resource, "arn:") || strings.ContainsAny(item.Check.Resource, "*?") || strings.ContainsAny(item.Check.Action, "*?") {
		return nil, "", errors.New("tightening requires a captured unused exact action and ARN with complete recorded activity coverage")
	}
	raw, err := json.Marshal(struct {
		Version   string `json:"Version"`
		Statement []struct {
			Sid      string `json:"Sid"`
			Effect   string `json:"Effect"`
			Action   string `json:"Action"`
			Resource string `json:"Resource"`
		} `json:"Statement"`
	}{Version: "2012-10-17", Statement: []struct {
		Sid      string `json:"Sid"`
		Effect   string `json:"Effect"`
		Action   string `json:"Action"`
		Resource string `json:"Resource"`
	}{{Sid: "RestrictCapturedUnusedPermission", Effect: "Deny", Action: item.Check.Action, Resource: item.Check.Resource}}})
	if err != nil {
		return nil, "", err
	}
	return raw, crypto.SHA256Hex(raw), nil
}
