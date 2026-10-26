// SPDX-License-Identifier: BUSL-1.1

package native_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector/native"
)

func TestDecodeTargetRejectsUnknownAndInlineSecretFields(t *testing.T) {
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"endpoint":"https://example.com","username":"admin","password":"inline"}`),
		json.RawMessage(`{"endpoint":"https://example.com","username":"admin","password_ref":"secret://a","typo":true}`),
		json.RawMessage(`{"endpoint":"https://example.com","username":"admin","password_ref":"secret://a","cert_path":"/x"}`),
		json.RawMessage(`[]`),
	} {
		if _, err := native.DecodeTarget("a10", raw); err == nil {
			t.Fatalf("DecodeTarget accepted closed-schema violation: %s", raw)
		}
	}
	if _, err := native.DecodeTarget("unknown-family", json.RawMessage(`{}`)); err == nil {
		t.Fatal("DecodeTarget accepted an unknown family")
	}
}

// Every shipped family builds from a valid target, takes its credentials only
// through Require, and names the credential when one cannot be resolved.
func TestBuildEveryShippedFamily(t *testing.T) {
	targets := map[string]string{
		"nginx": `{"profile":"p","cert_path":"/c","key_path":"/k"}`, "apache": `{"profile":"p","cert_path":"/c","key_path":"/k"}`,
		"caddy": `{"profile":"p","cert_path":"/c","key_path":"/k"}`, "traefik": `{"profile":"p","cert_path":"/c","key_path":"/k"}`,
		"postgresql": `{"profile":"p","cert_path":"/c","key_path":"/k"}`, "mysql": `{"profile":"p","cert_path":"/c","key_path":"/k"}`,
		"rabbitmq": `{"profile":"p","cert_path":"/c","key_path":"/k"}`, "elasticsearch": `{"profile":"p","cert_path":"/c","key_path":"/k"}`,
		"tomcat":                  `{"profile":"p","cert_path":"/c","key_path":"/k"}`,
		"iis":                     `{"profile":"p","binding":"*:443:","import_dir":"C:/import"}`,
		"haproxy":                 `{"profile":"p","crt_path":"/c.pem","config_path":"/h.cfg"}`,
		"postfix":                 `{"profile":"p","postfix_cert_path":"/pc","postfix_key_path":"/pk","dovecot_cert_path":"/dc","dovecot_key_path":"/dk"}`,
		"java-keystore":           `{"profile":"p","keystore_path":"/ks.jks","keystore_password_ref":"secret://ks","alias":"tls"}`,
		"envoy":                   `{"endpoint":"https://sds.example.com","secret_name":"tls"}`,
		"a10":                     `{"endpoint":"https://a10.example.com","username":"admin","password_ref":"secret://a10"}`,
		"f5":                      `{"endpoint":"https://f5.example.com","client_ssl_profile":"cs","username":"admin","password_ref":"secret://f5"}`,
		"netscaler":               `{"endpoint":"https://ns.example.com","username":"admin","password_ref":"secret://ns"}`,
		"kemp":                    `{"endpoint":"https://kemp.example.com","token_ref":"secret://kemp"}`,
		"cisco":                   `{"endpoint":"https://cisco.example.com","username":"admin","password_ref":"secret://cisco"}`,
		"fortigate":               `{"endpoint":"https://fg.example.com","token_ref":"secret://fg"}`,
		"paloalto":                `{"endpoint":"https://pa.example.com","api_key_ref":"secret://pa"}`,
		"aws-acm":                 `{"endpoint":"https://acm.us-east-1.amazonaws.com","region":"us-east-1","access_key_id":"AKIDEXAMPLE","secret_access_key_ref":"secret://aws"}`,
		"azure-keyvault":          `{"endpoint":"https://vault.vault.azure.net","bearer_token_ref":"secret://az"}`,
		"gcp-certificate-manager": `{"endpoint":"https://certificatemanager.googleapis.com","project":"p","location":"global","bearer_token_ref":"secret://gcp"}`,
	}
	for family, raw := range targets {
		target, err := native.DecodeTarget(family, json.RawMessage(raw))
		if err != nil {
			t.Fatalf("%s: decode: %v", family, err)
		}
		var asked []string
		require := func(ref, label string) ([]byte, error) {
			asked = append(asked, ref)
			return []byte("credential-for-" + ref), nil
		}
		built, destroy, err := native.Build(family, target, require)
		if err != nil || built == nil {
			t.Fatalf("%s: build: %v", family, err)
		}
		for _, d := range destroy {
			d.Destroy()
		}
		if closer, ok := built.(interface{ Close() }); ok {
			closer.Close()
		}
		for _, ref := range asked {
			if !strings.Contains(raw, `"`+ref+`"`) {
				t.Fatalf("%s asked for %q, which its target does not name", family, ref)
			}
		}
		if strings.Contains(raw, "_ref") && len(asked) == 0 {
			t.Fatalf("%s names a credential reference but never resolved it", family)
		}
		refused := errors.New("store unavailable")
		if len(asked) > 0 {
			if _, _, err := native.Build(family, target, func(string, string) ([]byte, error) { return nil, refused }); !errors.Is(err, refused) {
				t.Fatalf("%s: a credential failure = %v, want it wrapped", family, err)
			}
		}
	}
}
