package api

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/discovery/nhi"
	"trstctl.com/trstctl/internal/discovery/nhibehavior"
	"trstctl.com/trstctl/internal/discovery/oauthgrant"
)

func TestValidateDiscoverySourceRequiresCredentialReferences(t *testing.T) {
	_, err := validateDiscoverySourceRequest(discoverySourceRequest{
		Kind: "cloud_certificate",
		Name: "bad-inline-cloud-credential",
		Config: json.RawMessage(`{
			"providers":[{
				"provider":"aws-acm",
				"region":"us-east-1",
				"secret_access_key":"inline-secret"
			}]
		}`),
	})
	if err == nil {
		t.Fatal("inline cloud credential material must be rejected; use *_ref fields")
	}

	if _, err := validateDiscoverySourceRequest(discoverySourceRequest{
		Kind: "cloud_certificate",
		Name: "good-referenced-cloud-credential",
		Config: json.RawMessage(`{
			"providers":[{
				"provider":"aws-acm",
				"region":"us-east-1",
				"access_key_id_ref":"env:AWS_ACCESS_KEY_ID",
				"secret_access_key_ref":"env:AWS_SECRET_ACCESS_KEY"
			}]
		}`),
	}); err != nil {
		t.Fatalf("credential-reference cloud config was rejected: %v", err)
	}

	if _, err := validateDiscoverySourceRequest(discoverySourceRequest{
		Kind: "cloud_secret",
		Name: "good-referenced-cloud-secret-credential",
		Config: json.RawMessage(`{
			"providers":[{
				"provider":"aws-secrets-manager",
				"region":"us-east-1",
				"access_key_id_ref":"env:AWS_ACCESS_KEY_ID",
				"secret_access_key_ref":"env:AWS_SECRET_ACCESS_KEY"
			}]
		}`),
	}); err != nil {
		t.Fatalf("credential-reference cloud-secret config was rejected: %v", err)
	}
}

func TestValidateDiscoverySourceAcceptsCrossSurfaceNHIMetadataOnly(t *testing.T) {
	valid := json.RawMessage(`{
		"observations":[
			{"surface":"idp","system":"okta","external_id":"app/payments","principal":"payments-api","owner":"platform","credential_kind":"oauth_client","scopes":["payments.read"]},
			{"surface":"cloud","system":"aws-iam","external_id":"role/payments-prod","principal":"arn:aws:iam::111111111111:role/payments-prod","owner":"platform","credential_kind":"role"},
			{"surface":"saas","system":"github","external_id":"app/installations/42","principal":"payments-ci-app","owner":"devex","credential_kind":"github_app"},
			{"surface":"on_prem","system":"ldap","external_id":"svc-payments","principal":"svc-payments","owner":"identity","credential_kind":"service_account"},
			{"surface":"code","system":"github-code-search","external_id":"repo/payments/path/deploy.yaml","principal":"payments-deploy-key","owner":"devex","credential_kind":"deploy_key"},
			{"surface":"ci","system":"github-actions","external_id":"repo/payments/env/prod","principal":"payments-ci-token","owner":"devex","credential_kind":"workflow_identity"}
		]
	}`)
	if _, err := validateDiscoverySourceRequest(discoverySourceRequest{
		Kind:   nhi.SourceKind,
		Name:   "nhi-cross-surface",
		Config: valid,
	}); err != nil {
		t.Fatalf("cross-surface NHI metadata-only source was rejected: %v", err)
	}

	inlineSecret := json.RawMessage(`{
		"observations":[
			{"surface":"idp","system":"okta","external_id":"app/payments","principal":"payments-api","client_secret":"raw-value"}
		]
	}`)
	if _, err := validateDiscoverySourceRequest(discoverySourceRequest{
		Kind:   nhi.SourceKind,
		Name:   "bad-nhi-source",
		Config: inlineSecret,
	}); err == nil {
		t.Fatal("inline NHI credential material must be rejected; discovery config may carry metadata only")
	}
}

func TestValidateDiscoverySourceAcceptsOAuthGrantMetadataOnly(t *testing.T) {
	valid := json.RawMessage(`{
		"grants":[
			{
				"provider":"okta",
				"app_id":"0oa-payments",
				"app_name":"Payments BI Export",
				"principal":"payments-bi-export",
				"resource":"google-workspace",
				"scopes":["drive.readonly","admin.directory.user.readonly"],
				"consent_type":"admin",
				"third_party":true,
				"owner":"finance-platform"
			}
		]
	}`)
	if _, err := validateDiscoverySourceRequest(discoverySourceRequest{
		Kind:   oauthgrant.SourceKind,
		Name:   "oauth-grants",
		Config: valid,
	}); err != nil {
		t.Fatalf("OAuth grant metadata-only source was rejected: %v", err)
	}

	inlineSecret := json.RawMessage(`{
		"grants":[
			{"provider":"okta","app_id":"0oa-payments","client_secret":"raw-value","scopes":["drive.readonly"]}
		]
	}`)
	if _, err := validateDiscoverySourceRequest(discoverySourceRequest{
		Kind:   oauthgrant.SourceKind,
		Name:   "bad-oauth-grants",
		Config: inlineSecret,
	}); err == nil {
		t.Fatal("inline OAuth client credential material must be rejected; discovery config may carry grant metadata only")
	}
}

func TestValidateDiscoverySourceAcceptsNHIBehaviorMetadataOnly(t *testing.T) {
	valid := json.RawMessage(`{
		"events":[
			{"principal":"payments-api","occurred_at":"2026-06-01T10:00:00Z","ip":"198.51.100.10","geo":"US","user_agent":"payments-agent/1.0","action":"token_use","usage_count":10,"baseline":true},
			{"principal":"payments-api","occurred_at":"2026-06-02T02:15:00Z","ip":"203.0.113.9","geo":"DE","user_agent":"curl/8.7","action":"token_use","usage_count":90}
		],
		"business_hours":{"start_hour":8,"end_hour":18}
	}`)
	if _, err := validateDiscoverySourceRequest(discoverySourceRequest{
		Kind:   nhibehavior.SourceKind,
		Name:   "nhi-behavior",
		Config: valid,
	}); err != nil {
		t.Fatalf("NHI behavior metadata-only source was rejected: %v", err)
	}

	inlineSecret := json.RawMessage(`{
		"events":[
			{"principal":"payments-api","occurred_at":"2026-06-02T02:15:00Z","ip":"203.0.113.9","geo":"DE","token":"raw-value","usage_count":90}
		]
	}`)
	if _, err := validateDiscoverySourceRequest(discoverySourceRequest{
		Kind:   nhibehavior.SourceKind,
		Name:   "bad-nhi-behavior",
		Config: inlineSecret,
	}); err == nil {
		t.Fatal("inline behavior credential material must be rejected; NHI behavior config may carry metadata only")
	}
}
