// SPDX-License-Identifier: BUSL-1.1

package akeyless_test

import (
	"context"
	"encoding/pem"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/akeyless"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/secretstoretest"
)

// OD-13: an API-key access ID lists the static secrets under a folder across
// list-items pages with no value read; with content inspection the values of
// the listed items are fetched by name, and a certificate and an API key are
// found without either reaching metadata. A wrong access key fails the sign-in.
func TestAkeylessStaticSecretsMetadataAndInspectionOD13(t *testing.T) {
	der, _, err := ctlogtest.IssueCert("akeyless.od13.example", "akeyless.od13.example")
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	token := "gl" + "pat-" + strings.Repeat("Od13Akeyless", 3)[:24]
	stand := secretstoretest.NewAkeyless("p-access-id", "access-key", []secretstoretest.AkeylessItem{
		{Name: "/apps/db/password", Value: "plain", Tags: []string{"db", "prod"}},
		{Name: "/apps/payments/tls-cert", Value: certPEM},
		{Name: "/apps/payments/deploy-token", Value: token},
		{Name: "/other/outside", Value: "x"},
	})
	t.Cleanup(stand.Close)
	run := func(inspect bool, key string) ([]cloudsecret.Found, error) {
		t.Helper()
		e, err := akeyless.New(akeyless.Config{BaseURL: stand.URL(), HTTPClient: stand.Client(), AccessID: "p-access-id",
			AccessKey: cloudcert.StaticToken(key), PathPrefix: "/apps", InspectContent: inspect})
		if err != nil {
			t.Fatal(err)
		}
		return e.Enumerate(context.Background())
	}
	metadata, err := run(false, "access-key")
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
	if len(byName) != 3 || byName["/apps/db/password"]["tags"] != "db,prod" || byName["/apps/db/password"]["item_type"] != "STATIC_SECRET" {
		t.Fatalf("metadata = %+v", byName)
	}
	pages := 0
	for _, call := range stand.Seen() {
		switch call {
		case "POST /list-items":
			pages++
		case "POST /get-secret-value":
			t.Fatal("a metadata-only run read values")
		}
	}
	if pages != 2 {
		t.Fatalf("list-items pages = %d, want 2", pages)
	}
	inspected, err := run(true, "access-key")
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
		}
		for _, v := range f.Metadata {
			if strings.Contains(v, token) {
				t.Fatal("a finding carries the token")
			}
		}
	}
	if kinds["/apps/payments/deploy-token"] != "gitlab_token" || !strings.HasPrefix(kinds["/apps/payments/tls-cert"], "certificate:") || len(inspected) != 5 {
		t.Fatalf("inspected = %+v (%d findings)", kinds, len(inspected))
	}
	if _, err := run(false, "wrong"); err == nil || !strings.Contains(err.Error(), "status 401") || strings.Contains(err.Error(), "failed to authenticate") {
		t.Fatalf("wrong access key: %v", err)
	}
}

func TestAkeylessRefusesAnIncompleteSourceOD13(t *testing.T) {
	for name, cfg := range map[string]akeyless.Config{
		"no access id":  {AccessKey: cloudcert.StaticToken("k")},
		"no access key": {AccessID: "p-x"},
		"dot path":      {AccessID: "p-x", AccessKey: cloudcert.StaticToken("k"), PathPrefix: "/a/../b"},
	} {
		if _, err := akeyless.New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
