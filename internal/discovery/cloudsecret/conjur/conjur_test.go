// SPDX-License-Identifier: BUSL-1.1

package conjur_test

import (
	"context"
	"encoding/pem"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/conjur"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/secretstoretest"
)

// OD-13: a host inventories the variables it may read under a policy path
// from the resource listing alone (no value read); with content inspection
// each variable that holds a value is read once and a certificate and an
// API key are found, while an empty variable is reported as having no value.
// A variable outside the path or the host's privileges is not listed.
func TestConjurVariablesMetadataAndInspectionOD13(t *testing.T) {
	der, _, err := ctlogtest.IssueCert("conjur.od13.example", "conjur.od13.example")
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	token := "gl" + "pat-" + strings.Repeat("Od13Conjur", 3)[:24]
	stand := secretstoretest.NewConjur("od13", "host/apps/discovery", "host-api-key", []secretstoretest.ConjurVariable{
		{ID: "apps/db/password", Value: "plain", Visible: true, Annotations: map[string]string{"conjur/kind": "password"}},
		{ID: "apps/payments/tls-cert", Value: certPEM, Visible: true},
		{ID: "apps/payments/deploy-token", Value: token, Visible: true},
		{ID: "apps/empty/placeholder", Visible: true},
		{ID: "other/visible", Value: "x", Visible: true},
		{ID: "apps/hidden", Value: "y", Visible: false},
	})
	t.Cleanup(stand.Close)
	run := func(inspect bool, key string) ([]cloudsecret.Found, error) {
		t.Helper()
		e, err := conjur.New(conjur.Config{BaseURL: stand.URL(), HTTPClient: stand.Client(), Account: "od13", Login: "host/apps/discovery",
			APIKey: cloudcert.StaticToken(key), PathPrefix: "apps", InspectContent: inspect})
		if err != nil {
			t.Fatal(err)
		}
		return e.Enumerate(context.Background())
	}
	metadata, err := run(false, "host-api-key")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]map[string]string{}
	for _, f := range metadata {
		if f.Kind != cloudsecret.FindingKindSecretResource {
			t.Fatalf("metadata-only run found %s", f.Kind)
		}
		byName[f.SecretName] = f.Metadata
	}
	if len(byName) != 4 || byName["apps/db/password"]["conjur_kind"] != "password" || byName["apps/empty/placeholder"]["versions"] != "0" ||
		byName["apps/payments/tls-cert"]["latest_version"] != "1" {
		t.Fatalf("metadata = %+v", byName)
	}
	for _, call := range stand.Seen() {
		if strings.HasPrefix(call, "GET /secrets/") {
			t.Fatalf("a metadata-only run read a value: %s", call)
		}
	}
	stand.Reset()
	inspected, err := run(true, "host-api-key")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, f := range inspected {
		switch f.Kind {
		case cloudsecret.FindingKindAPIKey:
			kinds[f.SecretName] = f.Credential.Rule
		case cloudsecret.FindingKindCertificate:
			kinds[f.SecretName] = "certificate:" + f.Cert.Subject
		case cloudsecret.FindingKindSecretResource:
			if f.SecretName == "apps/empty/placeholder" && !strings.Contains(f.Metadata["content_unavailable_reason"], "no value") {
				t.Fatalf("empty variable = %+v", f.Metadata)
			}
		}
	}
	if kinds["apps/payments/deploy-token"] != "gitlab_token" || !strings.HasPrefix(kinds["apps/payments/tls-cert"], "certificate:") || len(inspected) != 6 {
		t.Fatalf("inspected = %+v (%d findings)", kinds, len(inspected))
	}
	reads := 0
	for _, call := range stand.Seen() {
		if strings.HasPrefix(call, "GET /secrets/od13/variable/") {
			reads++
		}
	}
	if reads != 3 {
		t.Fatalf("value reads = %d, want 3 (the empty variable is not read)", reads)
	}
	if _, err := run(false, "wrong-key"); err == nil || !strings.Contains(err.Error(), "status 401") {
		t.Fatalf("wrong API key: %v", err)
	}
}

func TestConjurRefusesAnIncompleteSourceOD13(t *testing.T) {
	key := cloudcert.StaticToken("k")
	for name, cfg := range map[string]conjur.Config{
		"no endpoint":     {Account: "a", Login: "host/x", APIKey: key},
		"no account":      {BaseURL: "https://conjur.example", Login: "host/x", APIKey: key},
		"no login":        {BaseURL: "https://conjur.example", Account: "a", APIKey: key},
		"no api key":      {BaseURL: "https://conjur.example", Account: "a", Login: "host/x"},
		"account slash":   {BaseURL: "https://conjur.example", Account: "a/b", Login: "host/x", APIKey: key},
		"dot path prefix": {BaseURL: "https://conjur.example", Account: "a", Login: "host/x", APIKey: key, PathPrefix: "apps/../x"},
	} {
		if _, err := conjur.New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
