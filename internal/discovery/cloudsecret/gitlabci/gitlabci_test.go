// SPDX-License-Identifier: BUSL-1.1

package gitlabci_test

import (
	"context"
	"encoding/pem"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/gitlabci"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/secretstoretest"
)

func TestGitLabCIVariablesMetadataAndInspection(t *testing.T) {
	der, _, err := ctlogtest.IssueCert("ci.a173.example", "ci.a173.example")
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	token := "gl" + "pat-" + strings.Repeat("A173lab", 4)[:24]
	stand := secretstoretest.NewGitLab("gl-a173", []secretstoretest.GitLabVariable{
		{Scope: "project:acme/api", Key: "DEPLOY_TOKEN", Value: token, Masked: true, Protected: true},
		{Scope: "project:acme/api", Key: "TLS_CERT", Value: certPEM, VariableType: "file", EnvironmentScope: "production"},
		{Scope: "project:acme/api", Key: "SIGNING_KEY", Value: "never-returned", Hidden: true},
		{Scope: "group:acme", Key: "REGION", Value: "us-east-1"},
	})
	t.Cleanup(stand.Close)
	run := func(inspect bool) []cloudsecret.Found {
		t.Helper()
		e, err := gitlabci.New(gitlabci.Config{BaseURL: stand.URL(), HTTPClient: stand.Client(), Project: "acme/api", Group: "acme", Token: cloudcert.StaticToken("gl-a173"), InspectContent: inspect})
		if err != nil {
			t.Fatal(err)
		}
		found, err := e.Enumerate(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return found
	}
	metadata := run(false)
	if len(metadata) != 4 {
		t.Fatalf("metadata-only = %+v", metadata)
	}
	for _, f := range metadata {
		if f.Kind != cloudsecret.FindingKindSecretResource {
			t.Fatalf("metadata-only run found %s", f.Kind)
		}
		for _, v := range f.Metadata {
			if strings.Contains(v, token) || strings.Contains(v, "BEGIN CERTIFICATE") {
				t.Fatal("metadata carries a value")
			}
		}
	}
	inspected := run(true)
	kinds := map[string]string{}
	for _, f := range inspected {
		switch f.Kind {
		case cloudsecret.FindingKindAPIKey:
			kinds[f.SecretName] = f.Credential.Rule
		case cloudsecret.FindingKindCertificate:
			kinds[f.SecretName] = "certificate:" + f.Cert.Subject
		case cloudsecret.FindingKindSecretResource:
			if f.SecretName == "SIGNING_KEY" && !strings.Contains(f.Metadata["content_unavailable_reason"], "hidden") {
				t.Fatalf("hidden variable = %+v", f.Metadata)
			}
			if f.SecretName == "TLS_CERT" && (f.Metadata["environment_scope"] != "production" || f.Metadata["variable_type"] != "file") {
				t.Fatalf("file variable = %+v", f.Metadata)
			}
		}
	}
	if kinds["DEPLOY_TOKEN"] != "gitlab_token" || !strings.HasPrefix(kinds["TLS_CERT"], "certificate:") || len(inspected) != 6 {
		t.Fatalf("inspected = %+v (%d findings)", kinds, len(inspected))
	}
	for _, call := range stand.Seen() {
		if !strings.HasPrefix(call, "GET /api/v4/projects/acme%2Fapi/variables?") && !strings.HasPrefix(call, "GET /api/v4/groups/acme/variables?") {
			t.Fatalf("unexpected call %s", call)
		}
	}
}

func TestGitLabCIRefusesAMissingScope(t *testing.T) {
	if _, err := gitlabci.New(gitlabci.Config{Token: cloudcert.StaticToken("x")}); err == nil {
		t.Fatal("a source with no project or group was accepted")
	}
}

// OD-2: instance-level variables are listed with an administrator's token,
// each body wiped and a value inspected only with content inspection; any
// other token's 403 fails the listing naming why.
func TestGitLabInstanceVariablesOD2(t *testing.T) {
	adminToken := "gl" + "pat-" + strings.Repeat("od2instance", 3)[:24]
	stand := secretstoretest.NewGitLabWithAdmin("maintainer-token", "admin-token", []secretstoretest.GitLabVariable{
		{Scope: "instance", Key: "INSTANCE_DEPLOY_TOKEN", Value: adminToken, Masked: true},
		{Scope: "instance", Key: "REGION", Value: "us-east-1"},
		{Scope: "group:acme", Key: "GROUP_ONLY", Value: "x"},
	})
	t.Cleanup(stand.Close)
	e, err := gitlabci.New(gitlabci.Config{BaseURL: stand.URL(), HTTPClient: stand.Client(), Instance: true, InspectContent: true,
		Token: cloudcert.StaticToken("admin-token")})
	if err != nil {
		t.Fatal(err)
	}
	found, err := e.Enumerate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(stand.URL(), "http://")
	kinds := map[string]int{}
	for _, f := range found {
		kinds[f.Kind]++
		if f.Metadata["scope"] != "instance" || f.Metadata["instance"] != host || f.Location != "instance" ||
			!strings.HasPrefix(f.Metadata["resource_id"], "gitlab://"+host+"/instance/variables/") {
			t.Fatalf("instance finding = %+v", f)
		}
		for _, v := range f.Metadata {
			if strings.Contains(v, adminToken) {
				t.Fatal("a finding carries the variable's value")
			}
		}
	}
	if kinds["cloud_secret_resource"] != 2 || kinds["secret_store_api_key"] != 1 || len(found) != 3 {
		t.Fatalf("found kinds %v (%d findings), want 2 resources and the inspected token", kinds, len(found))
	}
	if seen := stand.Seen(); len(seen) != 1 || seen[0] != "GET /api/v4/admin/ci/variables?per_page=100&page=1" {
		t.Fatalf("calls = %v", seen)
	}

	e, err = gitlabci.New(gitlabci.Config{BaseURL: stand.URL(), HTTPClient: stand.Client(), Group: "acme", Instance: true,
		Token: cloudcert.StaticToken("maintainer-token")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Enumerate(context.Background()); err == nil || !strings.Contains(err.Error(), "administrator") || !strings.Contains(err.Error(), "status 403") {
		t.Fatalf("a maintainer's token listing instance variables = %v, want the 403 named with the reason", err)
	}
	if _, err := gitlabci.New(gitlabci.Config{Token: cloudcert.StaticToken("x")}); err == nil || !strings.Contains(err.Error(), "instance") {
		t.Fatalf("no scope = %v, want the instance named among the scopes", err)
	}
}
