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

var fixtureGCPCommand = regexp.MustCompile(`curl --fail-with-body http://127\.0\.0\.1:(\d+)`)

func TestServedGatewayGCPServiceAccountA263(t *testing.T) {
	stand := newA263GCPStandIn(t)
	wire := map[string]any{"tenant_id": servedTestTenant, "id": "pam-gcp-provider", "type": "gcp-iam", "endpoint": stand.url, "project": "p", "service_account": a263GCPEmail, "bearer_token_ref": writeServedCredentialFile(t, "a263-gcp-admin", "a263-owned-admin"), "allowed_roles": []string{"reader"}, "max_ttl": "1h", "allow_insecure_loopback": true, "gateway": map[string]any{"endpoint": stand.url, "token_endpoint": stand.url + "/oauth/token", "scopes": []string{a263GCPScope}}}
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
	f := startGatewayFixture(t, gatewayFixtureOptions{gcp: registry})
	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/targets", f.operator, "a263-gcp-register", map[string]any{"id": "gcp-api", "target_type": "gcp", "provider_id": "pam-gcp-provider", "allowed_roles": []string{"reader"}, "gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": f.gatewayAddr}); status != http.StatusCreated {
		t.Fatalf("register GCP account = %d %s", status, body)
	}
	session := f.open("a263-gcp", map[string]any{"target_type": "gcp", "target_id": "gcp-api", "role": "reader", "ttl_seconds": 120})
	if session.Gateway == nil || session.Delivery != "gateway" {
		t.Fatal("GCP credential was not held by gateway")
	}
	defer func() {
		_, _ = secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a263-gcp-cleanup", map[string]any{"reason": "fixture complete"})
	}()
	out, stop := f.connect(session.ID, session.Gateway.Ticket, fixtureGCPCommand.MatchString)
	defer stop()
	otherID := uuid.NewString()
	registerServedTenantID(t, f.h.servedHarness, otherID, "A263 GCP other tenant")
	other := seedScopedTokenSubject(t, f.h.store, otherID, "other-reader", "access:read", "access:write")
	if status, _ := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID, other, nil); status != http.StatusNotFound {
		t.Fatal("another tenant read the GCP account session")
	}
	denied := map[string]any{"target_type": "gcp", "target_id": "gcp-api", "role": "administrator", "ttl_seconds": 120, "reason": "negative scope proof", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine"))}
	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", f.requester, "a263-gcp-denied-role", denied); status != http.StatusUnprocessableEntity {
		t.Fatalf("unauthorized GCP role = %d %s", status, body)
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
			t.Fatal("refused GCP gateway ticket admitted")
		}
	}
	refusedTicket(session.ID, "a263-wrong-ticket")

	port := fixtureGCPCommand.FindStringSubmatch(out)[1]
	query := exec.CommandContext(f.ctx, "curl", "--fail-with-body", "-sS", "http://127.0.0.1:"+port+"/storage/v1/b/owned-bucket/o/note?alt=media") // #nosec G204 G702 -- stock curl uses only the test-owned credential-free gateway tunnel (CWE-78)
	clientHome := t.TempDir()
	query.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + clientHome, "TMPDIR=" + clientHome}
	data, err := query.CombinedOutput()
	defer secret.Wipe(data)
	if err != nil || string(data) != stand.note {
		t.Fatalf("credential-free API read failed: %v", err)
	}
	if stand.keyCount() != 1 {
		t.Fatal("issued service-account key missing")
	}
	for _, variable := range query.Env {
		if strings.HasPrefix(variable, "GOOGLE_APPLICATION_CREDENTIALS=") || strings.HasPrefix(variable, "CLOUDSDK_AUTH_ACCESS_TOKEN=") {
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
	response, err := http.Get(stand.url + "/storage/v1/b/owned-bucket/o/note")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("direct unauthenticated target request admitted")
	}
	if status := stand.probe(t, "/storage/v1/b/owned-bucket/o/forbidden", false); status != http.StatusForbidden {
		t.Fatalf("OAuth permission bound = %d", status)
	}
	peer, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	_ = peer.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.WriteString(peer, "GET /storage/v1/b/owned-bucket/o/note?access_token=foreign&key=foreign HTTP/1.1\r\nHost: gateway\r\nAuthorization: Bearer foreign\r\nX-Goog-Api-Key: foreign\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	replies := bufio.NewReader(peer)
	live, err := http.ReadResponse(replies, nil)
	if err != nil || live.StatusCode != http.StatusOK {
		t.Fatal("live GCP API request failed")
	}
	_, _ = io.Copy(io.Discard, live.Body)
	_ = live.Body.Close()

	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/terminate", f.operator, "a263-gcp-terminate", map[string]any{"reason": "A263 proof"}); status != http.StatusAccepted {
		t.Fatalf("terminate = %d %s", status, body)
	}
	if _, err := replies.ReadByte(); err == nil {
		t.Fatal("terminated GCP connection remained open")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("GCP termination did not close the connection")
	}
	refusedTicket(session.ID, session.Gateway.Ticket)
	a201Await(t, "GCP exact key removed", func() bool { return stand.keyCount() == 0 })
	if status := stand.probe(t, "", true); status != http.StatusBadRequest {
		t.Fatalf("deleted key still issued a new grant = %d", status)
	}
	if status := stand.probe(t, "/storage/v1/b/owned-bucket/o/note", false); status != http.StatusOK {
		t.Fatalf("native residual token bound was hidden = %d", status)
	}
	a201Await(t, "same issued OAuth token reaches native expiry", func() bool {
		return stand.probe(t, "/storage/v1/b/owned-bucket/o/note", false) == http.StatusUnauthorized
	})

	a201Await(t, "GCP recording sealed", func() bool {
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording", f.requester, nil)
		return status == http.StatusOK && strings.Contains(string(body), `"status":"sealed"`)
	})
	if status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording/verify", f.requester, nil); status != http.StatusOK || !strings.Contains(string(body), `"verified":true`) {
		t.Fatal("GCP recording did not verify")
	}
	recording := recordingText(t, f.h, session.ID)
	if strings.Contains(recording, stand.note) || strings.Contains(recording, "PRIVATE KEY") || strings.Contains(recording, "a263-owned-admin") || strings.Contains(recording, "a263-owned-access-") {
		t.Fatal("GCP recording kept a credential/token")
	}
	if !strings.Contains(recording, "[masked:github-token]") {
		t.Fatal("GCP recording did not mask known token data")
	}
	_, read := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID, f.requester, nil)
	for _, text := range []string{out, string(read), f.gatewayLog.String()} {
		for _, bad := range []string{"PRIVATE KEY", "a263-owned-access-", "a263-owned-admin"} {
			if strings.Contains(text, bad) {
				t.Fatal("GCP credential reached client metadata or gateway logs")
			}
		}
	}
	expired := f.open("a263-gcp-expiry", map[string]any{"target_type": "gcp", "target_id": "gcp-api", "role": "reader", "ttl_seconds": 5})
	a201Await(t, "GCP exact session expires", func() bool { return f.sessionRead(expired.ID)["status"] == "expired" })
	refusedTicket(expired.ID, expired.Gateway.Ticket)
	a201Await(t, "expired GCP key removed", func() bool { return stand.keyCount() == 0 })

}
