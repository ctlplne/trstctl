// SPDX-License-Identifier: BUSL-1.1

package doppler_test

import (
	"context"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/discovery/cloudcert"
	"trstctl.com/trstctl/internal/discovery/cloudsecret"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/doppler"
	"trstctl.com/trstctl/internal/discovery/cloudsecret/secretstoretest"
)

func TestDopplerNamesWithoutValuesAndInspectionOD14(t *testing.T) {
	slack := "xo" + "xb-" + strings.Repeat("17310-", 7)[:36]
	stand := secretstoretest.NewDoppler("dp-a173", []secretstoretest.DopplerSecret{
		{Project: "backend", Config: "prd", Name: "SLACK_BOT_TOKEN", Value: slack},
		{Project: "backend", Config: "prd", Name: "LOG_LEVEL", Value: "info"},
		{Project: "backend", Config: "dev", Name: "SLACK_BOT_TOKEN", Value: slack},
		{Project: "web", Config: "prd", Name: "PUBLIC_URL", Value: "https://example.test"},
	})
	t.Cleanup(stand.Close)
	run := func(cfg doppler.Config) []cloudsecret.Found {
		t.Helper()
		cfg.BaseURL, cfg.HTTPClient, cfg.Token = stand.URL(), stand.Client(), cloudcert.StaticToken("dp-a173")
		e, err := doppler.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		found, err := e.Enumerate(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return found
	}
	if found := run(doppler.Config{}); len(found) != 4 {
		t.Fatalf("every project, metadata only = %+v", found)
	}
	for _, call := range stand.Seen() {
		if strings.HasPrefix(call, "GET /v3/configs/config/secrets?") {
			t.Fatalf("a metadata-only run read values: %s", call)
		}
	}
	found := run(doppler.Config{Project: "backend", Configs: []string{"prd", "dev"}, InspectContent: true})
	var fingerprints []string
	for _, f := range found {
		if f.Kind == cloudsecret.FindingKindAPIKey {
			fingerprints = append(fingerprints, f.Credential.Fingerprint)
			if f.Credential.Rule != "slack_token" || f.Credential.Field != "SLACK_BOT_TOKEN" {
				t.Fatalf("credential = %+v", f.Credential)
			}
		}
	}
	if len(fingerprints) != 2 || fingerprints[0] != fingerprints[1] || len(found) != 5 {
		t.Fatalf("inspected %d findings, fingerprints %v", len(found), fingerprints)
	}
	if _, err := doppler.New(doppler.Config{Configs: []string{"prd"}, Token: cloudcert.StaticToken("x")}); err == nil {
		t.Fatal("configs without a project were accepted")
	}
}
