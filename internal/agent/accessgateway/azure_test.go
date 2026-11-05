// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestAzureGrantBindsTenantApplicationScopeAndEscapesSecretBytes(t *testing.T) {
	value := []byte("owned+&=% secret-é-~")
	defer secret.Wipe(value)
	raw, err := json.Marshal(struct {
		Client string           `json:"client_id"`
		Tenant string           `json:"tenant_id"`
		Value  secret.JSONBytes `json:"client_secret"`
	}{"owned-client", "owned-tenant", value}) // #nosec G117 -- owned provider-envelope fixture; locked on parse and scratch wiped (CWE-200)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Wipe(raw)
	for _, pair := range [][2]string{{"foreign", "owned-tenant"}, {"owned-client", "foreign"}} {
		if m, err := parseAzureGatewayMaterial(raw, pair[0], pair[1]); err == nil {
			m.value.Destroy()
			t.Fatal("foreign Azure authority accepted")
		}
	}
	material, err := parseAzureGatewayMaterial(raw, "owned-client", "owned-tenant")
	if err != nil {
		t.Fatal(err)
	}
	defer material.value.Destroy()
	var body []byte
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		if r.URL.Path != "/owned-tenant/oauth2/v2.0/token" || r.Header.Get("Authorization") != "" {
			http.Error(w, "foreign authority", http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"owned-result","token_type":"Bearer","expires_in":5400}`)
	}))
	defer target.Close()
	defer func() { secret.Wipe(body) }()
	intent := SessionIntent{TargetType: TargetAzure, OAuthSubject: material.client, OAuthTenant: material.tenant, OAuthTokenEndpoint: target.URL + "/owned-tenant/oauth2/v2.0/token", OAuthScopes: []string{"https://graph.microsoft.com/.default"}, ExpiresAt: time.Now().Add(5 * time.Second)}
	token, expiry, err := azureExchange(context.Background(), material, intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	token.Destroy()
	if expiry.After(intent.ExpiresAt) {
		t.Fatal("native token lifetime extended local gateway access")
	}
	expected := []byte("grant_type=client_credentials&client_id=owned-client&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default&client_secret=")
	expected = append(expected, []byte("owned%2B%26%3D%25+secret-%C3%A9-~")...)
	defer secret.Wipe(expected)
	if !bytes.Equal(body, expected) {
		t.Fatal("Azure secret was not encoded exactly or grant authority changed")
	}
	material.value.Destroy()
	if token, _, err := azureExchange(context.Background(), material, intent, nil); err == nil {
		token.Destroy()
		t.Fatal("destroyed credential still minted a token")
	}
	intent.ExpiresAt = time.Now().Add(-time.Second)
	if token, _, err := azureExchange(context.Background(), material, intent, nil); err == nil {
		token.Destroy()
		t.Fatal("expired session minted a token")
	}
}
func TestAzureSessionIntentRejectsMixedOrUnboundAuthority(t *testing.T) {
	base := SessionIntent{SessionID: "owned", TargetID: "azure", TargetType: TargetAzure, RequiredAgentID: "gateway", CredentialRef: CredentialRef("owned"), TicketDigest: TicketDigest("ticket"), ExpiresAt: time.Now().Add(time.Minute), UpstreamURL: "https://graph.microsoft.com", OAuthTokenEndpoint: (&url.URL{Scheme: "https", Host: "login.microsoftonline.com", Path: "/owned-tenant/oauth2/v2.0/token"}).String(), OAuthTenant: "owned-tenant", OAuthSubject: "owned-client", OAuthScopes: []string{"https://graph.microsoft.com/.default"}}
	if err := ValidateSessionIntent(base); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*SessionIntent){func(i *SessionIntent) { i.OAuthTenant = "other" }, func(i *SessionIntent) { i.OAuthTenant = "" }, func(i *SessionIntent) { i.OAuthSubject = "" }, func(i *SessionIntent) { i.OAuthScopes = []string{"https://graph.microsoft.com/User.Read"} }, func(i *SessionIntent) { i.OAuthScopes = append(i.OAuthScopes, "https://management.azure.com/.default") }, func(i *SessionIntent) { i.TargetType = TargetGCP }, func(i *SessionIntent) { i.AWSService = "s3" }} {
		intent := base
		intent.OAuthScopes = append([]string(nil), base.OAuthScopes...)
		change(&intent)
		if ValidateSessionIntent(intent) == nil {
			t.Fatal("unbound or mixed Azure scope accepted")
		}
	}
}
func TestAzureLiteralMaskIncludesSpecialCredentialBytes(t *testing.T) {
	value := []byte("owned+&=% secret-é-~")
	defer secret.Wipe(value)
	raw := append([]byte("response: "), value...)
	defer secret.Wipe(raw)
	masked := maskCredentialHead(raw, len(raw), value)
	defer secret.Wipe(masked)
	if bytes.Contains(masked, value) || !bytes.Contains(masked, []byte("[masked:credential]")) {
		t.Fatal("exact application password reached recording text")
	}
}
func FuzzAzureGatewayCredentialEnvelope(f *testing.F) {
	f.Add([]byte("null"))
	f.Add([]byte(`{"tenant_id":"owned-tenant","client_id":"owned-client","client_secret":"owned"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		material, err := parseAzureGatewayMaterial(raw, "owned-client", "owned-tenant")
		if err == nil {
			if material.value.Len() == 0 || material.value.Len() > 32<<10 || !strings.EqualFold(material.tenant, "owned-tenant") {
				t.Fatal("unbound Azure credential")
			}
			material.value.Destroy()
		}
	})
}
