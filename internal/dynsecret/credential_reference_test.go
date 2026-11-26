// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

type referenceTestTransport func(*http.Request) (*http.Response, error)

type boundHostedPublicationProvider struct{ *HostedKeyBackend }

func (*boundHostedPublicationProvider) Name() string { return "fixture-hosted" }
func (p *boundHostedPublicationProvider) Generate(ctx context.Context, req GenerateRequest) (Credential, error) {
	ref, document, err := p.CreateCredential(ctx, req)
	return Credential{BackendRef: ref, Secret: document}, err
}
func (*boundHostedPublicationProvider) DynamicSecretProviderType() string { return "openrouter" }
func (p *boundHostedPublicationProvider) DynamicSecretBindsRole(role, binding string) bool {
	return p.bindings[role] == binding
}

func TestCR605HostedIssuedReferenceRetainsTargetBindingAtPublication(t *testing.T) {
	backend, _ := fakeHostedBackend(t)
	provider := &boundHostedPublicationProvider{backend}
	ref, _, err := backend.CreateCredential(t.Context(), GenerateRequest{
		Role: "inference", LeaseID: "lease-publication", PrincipalSuffix: testPrincipalSuffix("lease-publication"),
	})
	if err != nil {
		t.Fatal(err)
	}
	const document = `{"api_key":"value-key-1","key_hash":"key-1"}`
	canonical, err := NormalizeHostedReference(provider, "inference", ref)
	if err != nil || canonical != ref {
		t.Fatalf("publication lost the target binding: canonical=%q err=%v", canonical, err)
	}
	if err := ValidateIssuedHostedReference(provider, "inference", ref, []byte(document)); err != nil {
		t.Fatalf("target-bound issued key refused at publication: %v", err)
	}
	raw, _, err := opaqueFromBoundRef(ref, "openrouter", backend.api.endpoint, backend.adminIdentity)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateIssuedHostedReference(provider, "inference", raw, []byte(document)); err == nil {
		t.Fatal("new issuance admitted an old target-unbound reference")
	}
	if err := ValidateIssuedHostedReference(provider, "batch", ref, []byte(document)); err == nil {
		t.Fatal("issued key was published under a role with another binding")
	}
	if _, err := NormalizeHostedReference(provider, "inference", "v2:bad:trstctl:"+raw); err == nil {
		t.Fatal("malformed target binding passed reference admission")
	}
}

func (f referenceTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func referenceTestResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}
}

func referenceTestAdmin(t *testing.T) *secret.Buffer {
	t.Helper()
	admin, err := secret.NewFrom([]byte("fixture-management"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Destroy)
	return admin
}

func TestLegacyHostedCredentialDocumentKeepsProviderFamiliesDistinct(t *testing.T) {
	for _, tc := range []struct {
		name     string
		document string
		hosted   bool
	}{
		{"OpenRouter and LiteLLM", `{"api_key":"fixture-value","key_hash":"fixture-id"}`, true},
		{"Fireworks", `{"api_key":"fixture-value","key_id":"fixture-id","account_id":"fixture-account"}`, true},
		{"Supabase", `{"api_key":"fixture-value","key_id":"fixture-id","project_ref":"fixture-project"}`, true},
		{"Convex", `{"deploy_key":"fixture-value","key_name":"fixture-name"}`, true},
		{"dbt and Cloudflare", `{"token":"fixture-value","token_id":"fixture-id"}`, true},
		{"Cloudflare R2", `{"access_key_id":"fixture-id","secret_access_key":"fixture-value","endpoint":"https://fixture.invalid"}`, true},
		{"Okta and Databricks", `{"client_id":"fixture-client","client_secret":"fixture-value","secret_id":"fixture-id"}`, true},
		{"Datadog", `{"api_key":"fixture-value","key_id":"fixture-id","site":"fixture-site"}`, false},
		{"AWS STS", `{"access_key_id":"fixture-id","secret_access_key":"fixture-value","session_token":"fixture-token"}`, false},
		{"PostgreSQL DSN", `postgresql://fixture-role:fixture-value@fixture.invalid/fixture-db`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if LegacyHostedCredentialDocument([]byte(tc.document)) != tc.hosted {
				t.Fatalf("wrong historical credential family, want hosted=%t", tc.hosted)
			}
		})
	}
}

// CR-962. A management reference and an issued credential have different
// meanings, even when the provider puts the same bytes in both fields.
func TestHostedMintDisallowsCredentialInManagementID(t *testing.T) {
	const (
		marker = "fixture-value"
		hexID  = "aabbccddaabbccddaabbccddaabbccdd"
	)
	tests := []struct {
		name     string
		provider string
		binding  string
		keyName  string
		body     string
	}{
		{"OpenRouter top-level key", "openrouter", "unlimited", "fixture_key", `{"key":"fixture-value","data":{"hash":"id-fixture-value"}}`},
		{"OpenRouter second key", "openrouter", "unlimited", "fixture_key", `{"key":"fixture-other","data":{"hash":"fixture-value","key":"fixture-value"}}`},
		{"Fireworks", "fireworks", "fixture:bot", "fixture_key", `{"keyId":"fixture-value","key":"fixture-value"}`},
		{"Supabase", "supabase", "abcdefghijklmnopqrst", "fixture_key", `{"id":"fixture-value","api_key":"fixture-value"}`},
		{"Convex", "convex", "fixture-target", marker, `{"deployKey":"fixture-value"}`},
		{"dbt", "dbt", "42:member", "fixture_key", `{"data":{"id":42,"token_string":"42"}}`},
		{"Cloudflare", "cloudflare", "template:" + hexID, "fixture_key", `{"success":true,"result":{"id":"` + hexID + `","value":"` + hexID + `"}}`},
		{"R2 original", "cloudflare-r2", "account:" + hexID + ":" + hexID, "fixture_key", `{"success":true,"result":{"id":"` + hexID + `","value":"` + hexID + `"}}`},
		{"R2 derived", "cloudflare-r2", "account:" + hexID + ":" + hexID, "fixture_key", `{"success":true,"result":{"id":"` + crypto.SHA256Hex([]byte(marker)) + `","value":"fixture-value"}}`},
		{"Cloudflare ID shape", "cloudflare", "template:" + hexID, "fixture_key", `{"success":true,"result":{"id":"fixture-id","value":"fixture-value"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vendor := hostedKeyVendors[tt.provider].open(referenceTestAdmin(t))
			var createCalls int
			api := hostedAPI{name: tt.provider, endpoint: "https://fixture.invalid", client: &http.Client{
				Transport: referenceTestTransport(func(req *http.Request) (*http.Response, error) {
					if req.Method == http.MethodGet {
						return referenceTestResponse(http.StatusOK, `{"success":true,"result":{"policies":[{"effect":"allow","permission_groups":[{"id":"fixture-policy"}],"resources":{}}]}}`), nil
					}
					createCalls++
					return referenceTestResponse(http.StatusOK, tt.body), nil
				}),
			}}
			id, credential, err := vendor.mint(context.Background(), api, tt.binding, tt.keyName)
			defer secret.Wipe(credential)
			if createCalls != 1 {
				t.Fatalf("fixture observed %d mint requests", createCalls)
			}
			if err == nil || id != "" || len(credential) != 0 {
				t.Fatal("provider returned a reference or credential after failed ID admission")
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatal("admission error disclosed the marker")
			}
		})
	}
}

func TestClientSecretMintDisallowsCredentialInManagementID(t *testing.T) {
	admin := referenceTestAdmin(t)
	tests := []struct {
		name    string
		binding string
		vendor  clientSecretVendor
	}{
		{"okta", "fixture-app", oktaVendor{token: admin}},
		{"databricks", "fixture-account:42", &databricksVendor{secret: admin, clientID: "fixture-admin"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var createCalls int
			api := hostedAPI{name: tt.name, endpoint: "https://fixture.invalid", client: &http.Client{
				Transport: referenceTestTransport(func(req *http.Request) (*http.Response, error) {
					switch {
					case strings.HasSuffix(req.URL.Path, "/token"):
						return referenceTestResponse(http.StatusOK, `{"access_token":"fixture-authorization"}`), nil
					case req.Method == http.MethodGet:
						return referenceTestResponse(http.StatusOK, `{"credentials":{"oauthClient":{"client_id":"fixture-client"}},"applicationId":"fixture-client"}`), nil
					default:
						createCalls++
						return referenceTestResponse(http.StatusCreated, `{"id":"fixture-value","client_secret":"fixture-value","secret":"fixture-value","status":"ACTIVE"}`), nil
					}
				}),
			}}
			id, credential, err := tt.vendor.add(context.Background(), api, tt.binding)
			defer secret.Wipe(credential)
			if createCalls != 1 {
				t.Fatalf("fixture observed %d create requests", createCalls)
			}
			if err == nil || id != "" || len(credential) != 0 {
				t.Fatal("client-secret adapter returned a reference or credential after failed ID admission")
			}
		})
	}
}

// CR-663. LiteLLM returns different token encodings across versions. The
// management identity and protected document must agree in both cases.
func TestLiteLLMMintDerivesPublicManagementHandle(t *testing.T) {
	const material = "fixture-value"
	want := crypto.SHA256Hex([]byte(material))
	vendor := liteLLMVendor{master: referenceTestAdmin(t)}
	for _, tt := range []struct {
		name    string
		token   string
		refused bool
	}{
		{"legacy echo", material, false},
		{"canonical handle", want, false},
		{"different identity", "fixture-unrelated", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			api := hostedAPI{name: "litellm", endpoint: "https://fixture.invalid", client: &http.Client{
				Transport: referenceTestTransport(func(*http.Request) (*http.Response, error) {
					return referenceTestResponse(http.StatusOK, fmt.Sprintf(`{"key":%q,"token":%q}`, material, tt.token)), nil
				}),
			}}
			id, credential, err := vendor.mint(context.Background(), api, "all-models", "fixture-key")
			defer secret.Wipe(credential)
			if tt.refused {
				if err == nil || id != "" || len(credential) != 0 {
					t.Fatal("accepted conflicting provider identity")
				}
				return
			}
			if err != nil || id != want {
				t.Fatal("mint did not return the derived management hash")
			}
			var document struct {
				KeyHash string           `json:"key_hash"`
				APIKey  secret.JSONBytes `json:"api_key"`
			}
			defer func() { secret.Wipe(document.APIKey) }()
			if err := json.Unmarshal(credential, &document); err != nil ||
				document.KeyHash != want || !crypto.ConstantTimeEqual(document.APIKey, []byte(material)) {
				t.Fatal("protected document did not keep the credential and management handle separately")
			}
		})
	}
}

func TestHostedMintRejectsDuplicateRecognizedFields(t *testing.T) {
	vendor := openRouterVendor{management: referenceTestAdmin(t)}
	for name, body := range map[string]string{
		"case-folded field": `{"key":"fixture-one","KeY":"fixture-two","data":{"hash":"fixture-id"}}`,
		"escaped identity":  `{"key":"fixture-one","data":{"hash":"fixture-id","\u0068ash":"fixture-other"}}`,
		"enclosing object":  `{"key":"fixture-one","data":{"hash":"fixture-id"},"DaTa":{"hash":"fixture-other"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			api := hostedAPI{name: "openrouter", endpoint: "https://fixture.invalid", client: &http.Client{
				Transport: referenceTestTransport(func(*http.Request) (*http.Response, error) {
					return referenceTestResponse(http.StatusOK, body), nil
				}),
			}}
			id, credential, err := vendor.mint(context.Background(), api, "unlimited", "fixture-name")
			secret.Wipe(credential)
			if err == nil || id != "" || len(credential) != 0 {
				t.Fatal("duplicate vendor identity or secret field was accepted")
			}
		})
	}
}

// CR-588. The complete earlier-attempt set has to pass the provider's rule
// before the first replacement. This transport never reaches a network.
func TestCloudflareRejectsWholeEarlierAttemptSetBeforeAnyWrite(t *testing.T) {
	const goodID = "aabbccddaabbccddaabbccddaabbccdd"
	req := GenerateRequest{Role: "app", LeaseID: "fixture-lease", PrincipalSuffix: testPrincipalSuffix("fixture-lease")}
	for _, second := range []string{"", ".", "..", "fixture-wrong-shape"} {
		t.Run(fmt.Sprintf("length-%d-%s", len(second), second), func(t *testing.T) {
			var writes int
			var name string
			b, err := NewHostedKeyBackend("cloudflare", HostedKeyConfig{
				Endpoint: "https://fixture.invalid", AdminKey: []byte("fixture-admin"),
				RoleBindings: map[string]string{"app": "template " + goodID},
				HTTPClient: &http.Client{Transport: referenceTestTransport(func(req *http.Request) (*http.Response, error) {
					if req.Method != http.MethodGet {
						writes++
						return referenceTestResponse(http.StatusBadRequest, `{}`), nil
					}
					return referenceTestResponse(http.StatusOK, fmt.Sprintf(
						`{"success":true,"result":[{"id":%q,"name":%q},{"id":%q,"name":%q}],"result_info":{"total_pages":1}}`,
						goodID, name, second, name)), nil
				})},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			name, err = scopedNameForRequest(b.prefix, req, b.nameMax, b.nameSep)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := b.CreateCredential(context.Background(), req); err == nil || writes != 0 {
				t.Fatalf("malformed list should stop delivery, observed writes=%d", writes)
			}
		})
	}
}

func TestHostedReferenceErrorsDoNotCarryInputOrTransportDetail(t *testing.T) {
	backend, _ := fakeHostedBackend(t)
	if err := backend.Revoke(context.Background(), "fixture-unbound/fixture-value"); err == nil ||
		strings.Contains(err.Error(), "fixture-value") {
		t.Error("refusal did not return a safe reason")
	}
	api := hostedAPI{name: "litellm", endpoint: "https://fixture.invalid", client: &http.Client{
		Transport: referenceTestTransport(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("fixture-transport-detail")
		}),
	}}
	_, _, err := api.call(context.Background(), http.MethodGet, "/key/info?key=fixture-value", nil, nil)
	if err == nil || strings.Contains(err.Error(), "fixture-value") || strings.Contains(err.Error(), "fixture-transport-detail") {
		t.Fatal("transport error carried untrusted detail")
	}
}

func TestConvexPreflightsEveryMatchingKey(t *testing.T) {
	vendor := convexVendor{token: referenceTestAdmin(t)}
	api := hostedAPI{name: "convex", endpoint: "https://fixture.invalid", client: &http.Client{
		Transport: referenceTestTransport(func(*http.Request) (*http.Response, error) {
			return referenceTestResponse(http.StatusOK,
				`[{"name":"fixture-id"},{"name":"fixture-id","deployKey":"fixture-id"}]`), nil
		}),
	}}
	if ids, err := vendor.named(t.Context(), api, "fixture-deployment", "fixture-id"); err == nil || len(ids) != 0 {
		t.Fatal("an unproved later entry was ignored during earlier-attempt preflight")
	}
}

func TestDatabricksPreflightsEveryMatchingSecret(t *testing.T) {
	vendor := &databricksVendor{secret: referenceTestAdmin(t), clientID: "fixture-admin"}
	api := hostedAPI{name: "databricks", endpoint: "https://fixture.invalid", client: &http.Client{
		Transport: referenceTestTransport(func(req *http.Request) (*http.Response, error) {
			if strings.HasSuffix(req.URL.Path, "/token") {
				return referenceTestResponse(http.StatusOK, `{"access_token":"fixture-authorization"}`), nil
			}
			return referenceTestResponse(http.StatusOK,
				`{"secrets":[{"id":"fixture-id"},{"id":"fixture-id","secret":"fixture-id"}]}`), nil
		}),
	}}
	if found, err := vendor.present(t.Context(), api, "fixture-account:42", "fixture-id"); err == nil || found {
		t.Fatal("an unproved later entry was ignored while resolving the management identity")
	}
}
