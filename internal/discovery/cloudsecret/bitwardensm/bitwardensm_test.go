// SPDX-License-Identifier: BUSL-1.1

package bitwardensm_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/bitwardensm"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/secretstoretest"
)

// A machine account token in the SDK's format; its parts are joined at run
// time and it is not a live credential.
var standinToken = "0." + "5b3c1a2e-9f40-4d1b-8a6e-2c7d9e0f1a2b" + "." + "od13StandinClientSecret" + ":" + "AAECAwQFBgcICQoLDA0ODw=="

const orgID = "8e2f4c1a-7b3d-4e9f-a1c2-3d4e5f6a7b8c"

// OD-13: the machine account signs in, opens the organization key from the
// encrypted payload with its token's key, and lists the organization's
// secrets with their decrypted names and project names, reading no value;
// with content inspection the values are fetched by ID, decrypted, and a
// certificate and an API key are found without either reaching metadata. A
// token whose key opens nothing fails the run instead of inventorying
// unreadable names.
func TestBitwardenSecretsManagerMetadataAndInspectionOD13(t *testing.T) {
	der, _, err := ctlogtest.IssueCert("bitwarden.od13.example", "bitwarden.od13.example")
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	token := "gl" + "pat-" + strings.Repeat("Od13Bitwarden", 3)[:24]
	orgKey := bytes.Repeat([]byte{0x5a}, 64)
	stand := secretstoretest.NewBitwardenSecretsManager(standinToken, orgID, orgKey, []secretstoretest.BitwardenSecret{
		{ID: "a1000000-0000-4000-8000-000000000001", Key: "DB_PASSWORD", Value: "plain", Project: "payments"},
		{ID: "a1000000-0000-4000-8000-000000000002", Key: "TLS_CERT", Value: certPEM, Project: "payments"},
		{ID: "a1000000-0000-4000-8000-000000000003", Key: "DEPLOY_TOKEN", Value: token},
	})
	t.Cleanup(stand.Close)
	run := func(inspect bool, accessToken string) ([]cloudsecret.Found, error) {
		t.Helper()
		e, err := bitwardensm.New(bitwardensm.Config{BaseURL: stand.URL(), IdentityURL: stand.URL(), HTTPClient: stand.Client(),
			AccessToken: cloudcert.StaticToken(accessToken), InspectContent: inspect})
		if err != nil {
			t.Fatal(err)
		}
		return e.Enumerate(context.Background())
	}
	metadata, err := run(false, standinToken)
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
	if len(byName) != 3 || byName["TLS_CERT"]["project_names"] != "payments" || byName["DEPLOY_TOKEN"]["organization"] != orgID ||
		!strings.Contains(byName["DB_PASSWORD"]["resource_id"], "/organizations/"+orgID+"/secrets/a1000000-") {
		t.Fatalf("metadata = %+v", byName)
	}
	for _, call := range stand.Seen() {
		if strings.HasPrefix(call, "POST /secrets/get-by-ids") {
			t.Fatal("a metadata-only run read values")
		}
	}
	inspected, err := run(true, standinToken)
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
			if strings.Contains(v, token) || strings.Contains(v, "BEGIN CERTIFICATE") {
				t.Fatal("a finding carries a value")
			}
		}
	}
	if kinds["DEPLOY_TOKEN"] != "gitlab_token" || !strings.HasPrefix(kinds["TLS_CERT"], "certificate:") || len(inspected) != 5 {
		t.Fatalf("inspected = %+v (%d findings)", kinds, len(inspected))
	}
	// The same token ID and secret with another key seed: the identity service
	// signs it in, but its payload does not open.
	wrongSeed := strings.Split(standinToken, ":")[0] + ":" + "EBESExQVFhcYGRobHB0eHw=="
	stand2 := secretstoretest.NewBitwardenSecretsManager(standinToken, orgID, orgKey, nil)
	t.Cleanup(stand2.Close)
	e, err := bitwardensm.New(bitwardensm.Config{BaseURL: stand2.URL(), IdentityURL: stand2.URL(), HTTPClient: stand2.Client(),
		AccessToken: cloudcert.StaticToken(wrongSeed)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Enumerate(context.Background()); err == nil || !strings.Contains(err.Error(), "does not open") {
		t.Fatalf("a token whose key opens nothing: %v", err)
	}
	if _, err := run(false, "0.5b3c1a2e-9f40-4d1b-8a6e-2c7d9e0f1a2b.wrong:AAECAwQFBgcICQoLDA0ODw=="); err == nil || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("a wrong client secret: %v", err)
	}
	if _, err := run(false, "not-a-token"); err == nil || !strings.Contains(err.Error(), "malformed access token") {
		t.Fatalf("a malformed token: %v", err)
	}
}

func TestBitwardenSecretsManagerNeedsAnAccessTokenOD13(t *testing.T) {
	if _, err := bitwardensm.New(bitwardensm.Config{}); err == nil {
		t.Fatal("a source with no access token was accepted")
	}
	if _, err := bitwardensm.New(bitwardensm.Config{AccessToken: cloudcert.StaticToken("x"), IdentityURL: "::bad"}); err == nil {
		t.Fatal("a bad identity endpoint was accepted")
	}
}
