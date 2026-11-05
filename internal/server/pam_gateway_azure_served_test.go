// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"

	"trstctl.com/trstctl/internal/config"
)

var fixtureAzureCommand = regexp.MustCompile(`curl --fail-with-body http://127\.0\.0\.1:(\d+)`)

func TestServedGatewayAzureApplicationA263(t *testing.T) {
	stand := newA263AzureStandIn(t)
	wire := map[string]any{"tenant_id": servedTestTenant, "id": "pam-azure-provider", "type": "azure-entra", "endpoint": stand.url, "application_object_id": "owned-object", "application_client_id": a263AzureClient, "azure_tenant_id": a263AzureTenant, "authority_host": stand.url, "bearer_token_ref": writeServedCredentialFile(t, "a263-azure-admin", "a263-owned-admin"), "allowed_roles": []string{"reader"}, "max_ttl": "1h", "allow_insecure_loopback": true, "gateway": map[string]any{"endpoint": stand.url, "token_endpoint": stand.url + a263AzureTokenPath, "scopes": []string{a263AzureScope}}}

	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var provider config.DynamicSecretProviderConfig
	if json.Unmarshal(raw, &provider) != nil {
		t.Fatal("provider fixture decode")
	}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{provider}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := startGatewayFixture(t, gatewayFixtureOptions{azure: registry})
	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/targets", f.operator, "a263-azure-register", map[string]any{"id": "azure-api", "target_type": "azure", "provider_id": "pam-azure-provider", "allowed_roles": []string{"reader"}, "gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": f.gatewayAddr}); status != http.StatusCreated {
		t.Fatalf("register Azure account = %d %s", status, body)
	}
	session := f.open("a263-azure", map[string]any{"target_type": "azure", "target_id": "azure-api", "role": "reader", "ttl_seconds": 120})
	if session.Gateway == nil || session.Delivery != "gateway" {
		t.Fatal("Azure credential was not held by gateway")
	}
	defer func() {
		_, _ = secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a263-azure-cleanup", map[string]any{"reason": "fixture complete"})
	}()
	out, stop := f.connect(session.ID, session.Gateway.Ticket, fixtureAzureCommand.MatchString)
	defer stop()
	otherID := uuid.NewString()
	registerServedTenantID(t, f.h.servedHarness, otherID, "A263 Azure other tenant")
	other := seedScopedTokenSubject(t, f.h.store, otherID, "other-reader", "access:read", "access:write")
	if status, _ := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID, other, nil); status != http.StatusNotFound {
		t.Fatal("another tenant read the Azure account session")
	}
	denied := map[string]any{"target_type": "azure", "target_id": "azure-api", "role": "administrator", "ttl_seconds": 120, "reason": "negative scope proof", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine"))}
	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", f.requester, "a263-azure-denied-role", denied); status != http.StatusUnprocessableEntity {
		t.Fatalf("unauthorized Azure role = %d %s", status, body)
	}
	refusedTicket := func(id, ticket string) {
		wrong, err := mtls.GatewayDial(f.ctx, session.Gateway.Address, []byte(session.Gateway.CAPEM), session.Gateway.SPIFFEID)
		if err != nil {
			t.Fatal(err)
		}
		_ = wrong.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = io.WriteString(wrong, "TRSTCTL-GATEWAY/1 "+id+" "+ticket+"\n")
		if err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(wrong).ReadString('\n')
		_ = wrong.Close()
		if err != nil || !strings.HasPrefix(line, "DENY ") {
			t.Fatal("refused Azure gateway ticket admitted")
		}
	}
	refusedTicket(session.ID, "a263-wrong-ticket")

	port := fixtureAzureCommand.FindStringSubmatch(out)[1]
	query := exec.CommandContext(f.ctx, "curl", "--fail-with-body", "-sS", "http://127.0.0.1:"+port+"/v1.0/organization?alt=media") // #nosec G204 G702 -- stock curl uses only the test-owned credential-free gateway tunnel (CWE-78)
	clientHome := t.TempDir()
	query.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + clientHome, "TMPDIR=" + clientHome}
	data, err := query.CombinedOutput()
	defer secret.Wipe(data)
	if err != nil || !bytes.Contains(data, []byte(stand.note)) {
		t.Fatalf("credential-free API read failed: %v", err)
	}
	if stand.credentialCount() != 1 {
		t.Fatal("issued application password missing")
	}
	for _, variable := range query.Env {
		if strings.HasPrefix(variable, "AZURE_CLIENT_CERTIFICATE_PATH=") || strings.HasPrefix(variable, "AZURE_CLIENT_SECRET=") {
			t.Fatal("client required a cloud credential")
		}
	}
	clientFiles, err := os.OpenRoot(clientHome)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientFiles.Close() }()
	if err := filepath.WalkDir(clientHome, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(clientHome, path)
		if err != nil {
			return err
		}
		raw, err := clientFiles.ReadFile(relative)
		defer secret.Wipe(raw)
		if err != nil {
			return err
		}
		if bytes.Contains(raw, []byte("PRIVATE KEY")) || bytes.Contains(raw, []byte("a263-owned-access-")) {
			t.Fatal("cloud credential written to client file")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	response, err := http.Get(stand.url + "/v1.0/organization")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("direct unauthenticated target request admitted")
	}
	if status := stand.probe(t, "/v1.0/users", false); status != http.StatusForbidden {
		t.Fatalf("OAuth permission bound = %d", status)
	}
	peer, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	_ = peer.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.WriteString(peer, "GET /v1.0/organization?access_token=foreign&key=foreign HTTP/1.1\r\nHost: gateway\r\nAuthorization: Bearer foreign\r\nX-Ms-Authorization-Auxiliary: foreign\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	replies := bufio.NewReader(peer)
	live, err := http.ReadResponse(replies, nil)
	if err != nil || live.StatusCode != http.StatusOK {
		t.Fatal("live Azure API request failed")
	}
	_, _ = io.Copy(io.Discard, live.Body)
	_ = live.Body.Close()

	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/terminate", f.operator, "a263-azure-terminate", map[string]any{"reason": "A263 proof"}); status != http.StatusAccepted {
		t.Fatalf("terminate = %d %s", status, body)
	}
	if _, err := replies.ReadByte(); err == nil {
		t.Fatal("terminated Azure connection remained open")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("Azure termination did not close the connection")
	}
	refusedTicket(session.ID, session.Gateway.Ticket)
	a201Await(t, "Azure exact password removed", func() bool { return stand.credentialCount() == 0 })
	if status := stand.probe(t, "", true); status != http.StatusUnauthorized {
		t.Fatalf("deleted password still issued a new grant = %d", status)
	}
	if status := stand.probe(t, "/v1.0/organization", false); status != http.StatusOK {
		t.Fatalf("native residual token bound was hidden = %d", status)
	}
	a201Await(t, "same issued OAuth token reaches native expiry", func() bool {
		return stand.probe(t, "/v1.0/organization", false) == http.StatusUnauthorized
	})

	a201Await(t, "Azure recording sealed", func() bool {
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording", f.requester, nil)
		return status == http.StatusOK && strings.Contains(string(body), `"status":"sealed"`)
	})
	if status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording/verify", f.requester, nil); status != http.StatusOK || !strings.Contains(string(body), `"verified":true`) {
		t.Fatal("Azure recording did not verify")
	}
	recording := recordingText(t, f.h, session.ID)
	if strings.Contains(recording, stand.note) || strings.Contains(recording, "PRIVATE KEY") || strings.Contains(recording, "a263-owned-admin") || strings.Contains(recording, "a263-owned-access-") {
		t.Fatal("Azure recording kept a credential/token")
	}
	if !strings.Contains(recording, "[masked:github-token]") {
		t.Fatal("Azure recording did not mask known token data")
	}
	_, read := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID, f.requester, nil)
	for _, text := range []string{out, string(read), f.gatewayLog.String()} {
		for _, bad := range []string{"PRIVATE KEY", "a263-owned-access-", "a263-owned-admin", "owned+&=% secret-é-"} {
			if strings.Contains(text, bad) {
				t.Fatal("Azure credential reached client metadata or gateway logs")
			}
		}
	}
	expired := f.open("a263-azure-expiry", map[string]any{"target_type": "azure", "target_id": "azure-api", "role": "reader", "ttl_seconds": 5})
	a201Await(t, "Azure exact session expires", func() bool { return f.sessionRead(expired.ID)["status"] == "expired" })
	refusedTicket(expired.ID, expired.Gateway.Ticket)
	a201Await(t, "expired Azure password removed", func() bool { return stand.credentialCount() == 0 })

}
