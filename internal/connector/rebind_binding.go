// SPDX-License-Identifier: BUSL-1.1

package connector

import (
	"encoding/json"
	"strings"
)

// RebindBindingMissing names the target configuration a re-bind-capable family
// needs before its deploys become fingerprint-named and re-bindable, or
// returns "" when the target has it (or the family needs none). Rollback
// readiness says so to the operator, and a relay refuses the rollback with it
// before redeeming anything (A166-L2-T1): such a target's rollback answers
// ErrRollbackNotConfigured, so a credential redeemed for it would be material
// outside the seal for nothing.
func RebindBindingMissing(family string, config json.RawMessage) string {
	var fields struct {
		BindTo              string `json:"bind_to"`
		SSLTLSProfile       string `json:"ssl_tls_profile"`
		CommitAdmin         string `json:"commit_admin"`
		CertificateMapEntry string `json:"certificate_map_entry"`
		NodeHostname        string `json:"node_hostname"`
		ListenerARN         string `json:"listener_arn"`
	}
	_ = json.Unmarshal(config, &fields)
	switch family {
	case "gcp-certificate-manager":
		if strings.TrimSpace(fields.CertificateMapEntry) == "" {
			return "this gcp-certificate-manager target names no certificate_map_entry (\"<map>/<entry>\"); its deploys patch the target-named certificate in place and leave no predecessor to re-bind"
		}
	case "fortigate":
		if strings.TrimSpace(fields.BindTo) == "" {
			return "this fortigate target names no bind_to (admin or ssl-vpn); its deploys install in place under the target name and leave no predecessor to re-bind"
		}
	case "paloalto":
		if strings.TrimSpace(fields.SSLTLSProfile) == "" || strings.TrimSpace(fields.CommitAdmin) == "" {
			return "this paloalto target names no ssl_tls_profile with commit_admin; its imports land in place under the target name and leave no predecessor to re-bind"
		}
	case "aws-acm":
		if strings.TrimSpace(fields.ListenerARN) == "" {
			return "this aws-acm target names no listener_arn, so it re-imports in place under one certificate ARN, which keeps no previous version to re-bind"
		}
	case "cisco":
		if strings.TrimSpace(fields.NodeHostname) == "" {
			return "this cisco target names no node_hostname with certificate_roles; its imports land in place under the target name and leave no predecessor to re-bind"
		}
	}
	return ""
}
