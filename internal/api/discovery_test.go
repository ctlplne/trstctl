package api

import (
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/discovery/compromise"
	"trstctl.com/trstctl/internal/discovery/nhi"
	"trstctl.com/trstctl/internal/discovery/nhibehavior"
	"trstctl.com/trstctl/internal/discovery/oauthgrant"
	"trstctl.com/trstctl/internal/discovery/serviceaccount"
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

func TestValidateDiscoverySourceAcceptsServiceAccountMetadataOnly(t *testing.T) {
	valid := json.RawMessage(`{
		"accounts":[
			{
				"surface":"active_directory",
				"provider":"ad",
				"directory":"corp.example",
				"account_id":"S-1-5-21-1000",
				"principal":"svc-payments@corp.example",
				"owner":"identity",
				"groups":["CN=Payments,OU=Service Accounts,DC=corp,DC=example"],
				"credential_refs":["ad:corp.example:svc-payments"]
			},
			{
				"surface":"cloud",
				"provider":"aws-iam",
				"directory":"111111111111",
				"account_id":"role/payments-prod",
				"principal":"arn:aws:iam::111111111111:role/payments-prod",
				"owner":"platform",
				"privileged":true,
				"roles":["AdministratorAccess"],
				"credential_refs":["aws:iam:role/payments-prod"]
			}
		]
	}`)
	if _, err := validateDiscoverySourceRequest(discoverySourceRequest{
		Kind:   serviceaccount.SourceKind,
		Name:   "service-accounts",
		Config: valid,
	}); err != nil {
		t.Fatalf("service-account metadata-only source was rejected: %v", err)
	}

	inlineSecret := json.RawMessage(`{
		"accounts":[
			{"surface":"ad","provider":"ad","account_id":"svc-payments","principal":"svc-payments","password":"raw-value"},
			{"surface":"cloud","provider":"aws-iam","account_id":"role/payments-prod","principal":"arn:aws:iam::111111111111:role/payments-prod"}
		]
	}`)
	if _, err := validateDiscoverySourceRequest(discoverySourceRequest{
		Kind:   serviceaccount.SourceKind,
		Name:   "bad-service-accounts",
		Config: inlineSecret,
	}); err == nil {
		t.Fatal("inline service-account credential material must be rejected; discovery config may carry references only")
	}

	adOnly := json.RawMessage(`{"accounts":[{"surface":"ad","provider":"ad","account_id":"svc-payments","principal":"svc-payments"}]}`)
	if _, err := validateDiscoverySourceRequest(discoverySourceRequest{
		Kind:   serviceaccount.SourceKind,
		Name:   "ad-only-service-accounts",
		Config: adOnly,
	}); err == nil {
		t.Fatal("service-account discovery must require both AD and cloud account observations")
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

func TestValidateDiscoverySourceAcceptsCompromisedCredentialMetadataOnly(t *testing.T) {
	valid := json.RawMessage(`{
		"signals":[
			{
				"principal":"payments-api",
				"credential_ref":"api-token:payments-ci",
				"credential_kind":"api_token",
				"provider":"github-actions",
				"detector":"honeytoken",
				"observed_at":"2026-06-03T03:15:00Z",
				"reason":"revoked token replayed from unfamiliar network",
				"confidence":"critical",
				"evidence_refs":["audit:api-token-use/evt-42"],
				"ip":"203.0.113.44",
				"geo":"DE",
				"user_agent":"curl/8.7"
			}
		]
	}`)
	if _, err := validateDiscoverySourceRequest(discoverySourceRequest{
		Kind:   compromise.SourceKind,
		Name:   "compromised-credentials",
		Config: valid,
	}); err != nil {
		t.Fatalf("compromised-credential metadata-only source was rejected: %v", err)
	}

	inlineSecret := json.RawMessage(`{
		"signals":[
			{
				"principal":"payments-api",
				"credential_ref":"api-token:payments-ci",
				"credential_kind":"api_token",
				"provider":"github-actions",
				"detector":"secret-scanner",
				"observed_at":"2026-06-03T03:15:00Z",
				"reason":"known leak",
				"confidence":"high",
				"evidence_refs":["scanner:evt-1"],
				"token_value":"raw-token-value"
			}
		]
	}`)
	if _, err := validateDiscoverySourceRequest(discoverySourceRequest{
		Kind:   compromise.SourceKind,
		Name:   "bad-compromised-credentials",
		Config: inlineSecret,
	}); err == nil {
		t.Fatal("inline stolen-token material must be rejected; compromised-credential config may carry metadata only")
	}
}

func TestValidateDiscoverySourceAcceptsKubernetesIngressGatewayMetadataOnly(t *testing.T) {
	valid := json.RawMessage(`{
		"resources":[
			{"kind":"Ingress","api_version":"networking.k8s.io/v1","namespace":"payments","name":"payments-web","tls_secret_name":"payments-web-tls","hosts":["payments.example.com"],"auto_issue":true},
			{"kind":"Gateway","api_version":"gateway.networking.k8s.io/v1","namespace":"edge","name":"public","tls_secret_name":"edge-public-tls","hosts":["edge.example.com","api.example.com"],"auto_issue":true}
		]
	}`)
	if _, err := validateDiscoverySourceRequest(discoverySourceRequest{
		Kind:   "k8s_ingress_gateway",
		Name:   "k8s-ingress-gateway",
		Config: valid,
	}); err != nil {
		t.Fatalf("Kubernetes ingress/gateway metadata-only source was rejected: %v", err)
	}

	inlineSecret := json.RawMessage(`{
		"resources":[
			{"kind":"Ingress","namespace":"payments","name":"payments-web","tls_secret_name":"payments-web-tls","hosts":["payments.example.com"],"private_key":"raw-value"}
		]
	}`)
	if _, err := validateDiscoverySourceRequest(discoverySourceRequest{
		Kind:   "k8s_ingress_gateway",
		Name:   "bad-k8s-ingress-gateway",
		Config: inlineSecret,
	}); err == nil {
		t.Fatal("inline Kubernetes TLS credential material must be rejected; discovery config may carry metadata only")
	}
}
