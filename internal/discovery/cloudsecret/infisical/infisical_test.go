// SPDX-License-Identifier: BUSL-1.1

package infisical_test

import (
	"context"
	"encoding/pem"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/infisical"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/secretstoretest"
)

// OD-13: a Universal Auth identity inventories every environment's secrets
// below the path, folders included, with no value asked for or kept; with
// content inspection a certificate and an API key are found and no value
// reaches a finding's metadata. A wrong client secret fails the sign-in
// without echoing the response.
func TestInfisicalSecretsMetadataAndInspectionOD13(t *testing.T) {
	der, _, err := ctlogtest.IssueCert("infisical.od13.example", "infisical.od13.example")
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	token := "gl" + "pat-" + strings.Repeat("Od13Infisical", 3)[:24]
	stand := secretstoretest.NewInfisical("ua-client", "ua-secret", []secretstoretest.InfisicalProject{
		{ID: "p-1", Name: "payments", Environments: []string{"dev", "prod"}},
	}, []secretstoretest.InfisicalSecret{
		{Project: "p-1", Environment: "dev", Path: "/", Key: "DB_PASSWORD", Value: "plain", Tags: []string{"db"}},
		{Project: "p-1", Environment: "dev", Path: "/payments", Key: "TLS_CERT", Value: certPEM, Version: 3},
		{Project: "p-1", Environment: "dev", Path: "/payments", Key: "DEPLOY_TOKEN", Value: token},
		{Project: "p-1", Environment: "prod", Path: "/", Key: "PROD_ONLY", Value: "x"},
	})
	t.Cleanup(stand.Close)
	run := func(cfg infisical.Config) ([]cloudsecret.Found, error) {
		t.Helper()
		cfg.BaseURL, cfg.HTTPClient = stand.URL(), stand.Client()
		if cfg.Token == nil {
			cfg.ClientID = "ua-client"
		}
		e, err := infisical.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return e.Enumerate(context.Background())
	}
	metadata, err := run(infisical.Config{ClientSecret: cloudcert.StaticToken("ua-secret")})
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]map[string]string{}
	for _, f := range metadata {
		if f.Kind != cloudsecret.FindingKindSecretResource {
			t.Fatalf("metadata-only run found %s", f.Kind)
		}
		for _, v := range f.Metadata {
			if strings.Contains(v, token) || strings.Contains(v, "BEGIN CERTIFICATE") || v == secretstoretest.InfisicalHiddenValue {
				t.Fatal("metadata carries a value")
			}
		}
		names[f.Metadata["environment"]+f.Metadata["secret_path"]+"/"+f.SecretName] = f.Metadata
	}
	if len(names) != 4 || names["dev/payments/TLS_CERT"]["version"] != "3" || names["dev//DB_PASSWORD"]["tags"] != "db" ||
		names["prod//PROD_ONLY"]["project_name"] != "payments" {
		t.Fatalf("metadata = %+v", names)
	}
	for _, call := range stand.Seen() {
		if strings.HasPrefix(call, "GET /api/v4/secrets?") && !strings.Contains(call, "viewSecretValue=false") {
			t.Fatalf("a metadata-only run asked for values: %s", call)
		}
	}
	stand.Reset()
	inspected, err := run(infisical.Config{ClientSecret: cloudcert.StaticToken("ua-secret"), Project: "p-1", Environments: []string{"dev"},
		SecretPath: "/payments", InspectContent: true})
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
	if kinds["DEPLOY_TOKEN"] != "gitlab_token" || !strings.HasPrefix(kinds["TLS_CERT"], "certificate:") || len(inspected) != 4 {
		t.Fatalf("inspected = %+v (%d findings)", kinds, len(inspected))
	}
	// An access token works instead of Universal Auth; a wrong secret fails.
	if _, err := run(infisical.Config{Token: cloudcert.StaticToken("infisical-standin-access-token"), Project: "p-1"}); err != nil {
		t.Fatalf("access token run: %v", err)
	}
	if _, err := run(infisical.Config{ClientSecret: cloudcert.StaticToken("wrong")}); err == nil || !strings.Contains(err.Error(), "status 401") ||
		strings.Contains(err.Error(), "Invalid credentials") {
		t.Fatalf("wrong client secret: %v", err)
	}
}

func TestInfisicalRefusesAnIncompleteSourceOD13(t *testing.T) {
	for name, cfg := range map[string]infisical.Config{
		"no credentials":               {},
		"client id without a secret":   {ClientID: "x"},
		"both token and client":        {ClientID: "x", ClientSecret: cloudcert.StaticToken("y"), Token: cloudcert.StaticToken("z")},
		"environments with no project": {Token: cloudcert.StaticToken("z"), Environments: []string{"dev"}},
		"relative path":                {Token: cloudcert.StaticToken("z"), SecretPath: "payments"},
		"dot path":                     {Token: cloudcert.StaticToken("z"), SecretPath: "/a/../b"},
	} {
		if _, err := infisical.New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
