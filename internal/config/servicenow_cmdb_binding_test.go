// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"
)

func TestServiceNowCMDBRelayBindingAcceptsSecretReference(t *testing.T) {
	cfg := Default()
	cfg.ITSM.ServiceNow.Bindings = []ServiceNowBinding{{ // #nosec G101 -- reference name only; no credential value (CWE-798)
		InstanceURL: "https://cmdb.qa.invalid",
		TokenRef:    "secret://cmdb/qa-token",
		RelayOnly:   true,
	}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("documented CMDB relay secret reference rejected: %v", err)
	}
}

func TestServiceNowBindingRejectsMalformedSecretReference(t *testing.T) {
	cfg := Default()
	cfg.ITSM.ServiceNow.Bindings = []ServiceNowBinding{{
		InstanceURL: "https://cmdb.qa.invalid",
		TokenRef:    "secret://",
		RelayOnly:   true,
	}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "token_ref") {
		t.Fatalf("malformed secret reference was not rejected: %v", err)
	}
}

func TestServiceNowRelayBindingKeepsControlPlaneEgressClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		binding ServiceNowBinding
	}{
		{"secret without relay purpose", ServiceNowBinding{InstanceURL: "https://cmdb.qa.invalid", TokenRef: "secret://cmdb/qa-token"}},                                                                                                         // #nosec G101 -- reference name only; no credential value (CWE-798)
		{"env ref on relay", ServiceNowBinding{InstanceURL: "https://cmdb.qa.invalid", TokenRef: "env:QA_TOKEN", RelayOnly: true}},                                                                                                              // #nosec G101 -- variable name only; no credential value (CWE-798)
		{"relay grants private control-plane egress", ServiceNowBinding{InstanceURL: "https://cmdb.qa.invalid", TokenRef: "secret://cmdb/qa-token", RelayOnly: true, AllowPrivateEndpoint: true, PrivateEgressCIDRs: []string{"127.0.0.1/32"}}}, // #nosec G101 -- reference name only; no credential value (CWE-798)
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.ITSM.ServiceNow.Bindings = []ServiceNowBinding{tc.binding}
			if err := cfg.Validate(); err == nil {
				t.Fatal("invalid ServiceNow binding was accepted")
			}
		})
	}
}
