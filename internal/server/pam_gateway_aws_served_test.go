// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/google/uuid"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"

	"trstctl.com/trstctl/internal/config"
)

var fixtureAWSCommand = regexp.MustCompile(`aws --no-sign-request --endpoint-url http://127\.0\.0\.1:(\d+)`)

// A263 native LocalStack AssumeRole/S3 wire proof. LocalStack does not enforce
// IAM; signature/permission enforcement must be separately proven by a stand-in.
func TestServedGatewayAWSSTSAccountA263(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if out, err := exec.Command("docker", "image", "inspect", a202LocalStackImage).CombinedOutput(); err != nil {
		t.Skipf("approved LocalStack image unavailable: %v %s", err, out)
	} // #nosec G204 -- fixed local Docker tool and approved fixture image (CWE-78)
	target, address := a201Container(t, "4566", "-e", "SERVICES=iam,sts,s3", a202LocalStackImage)
	endpoint := "http://" + address
	a201Await(t, "AWS lab IAM/STS/S3", func() bool {
		response, err := http.Get(endpoint + "/_localstack/health")
		if err != nil {
			return false
		}
		defer func() { _ = response.Body.Close() }()
		var health struct{ Services map[string]string }
		if json.NewDecoder(response.Body).Decode(&health) != nil {
			return false
		}
		for _, service := range []string{"iam", "sts", "s3"} {
			if health.Services[service] != "running" && health.Services[service] != "available" {
				return false
			}
		}
		return true
	})
	native := func(args ...string) string {
		t.Helper()
		out, err := a201Exec(target, append([]string{"awslocal"}, args...)...)
		if err != nil {
			t.Fatalf("owned AWS fixture call: %v %s", err, out)
		}
		return out
	}
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}]}`
	native("iam", "create-role", "--role-name", "a263-reader", "--assume-role-policy-document", trust)
	native("iam", "put-role-policy", "--role-name", "a263-reader", "--policy-name", "read-note", "--policy-document", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::a263-gateway/note"}]}`)
	native("s3api", "create-bucket", "--bucket", "a263-gateway")
	if out, err := a201Exec(target, "sh", "-c", "printf 'a263-owned-note' > /tmp/a263-source-note"); err != nil {
		t.Fatalf("owned fixture note: %v %s", err, out)
	}
	native("s3api", "put-object", "--bucket", "a263-gateway", "--key", "note", "--body", "/tmp/a263-source-note")
	stand := newA263AWSStandIn(t, endpoint)
	wire := map[string]any{"tenant_id": servedTestTenant, "id": "pam-aws-provider", "type": "aws-sts", "endpoint": stand.url, "iam_endpoint": stand.url, "region": "us-east-1", "access_key_id": "test", "secret_access_key_ref": writeServedCredentialFile(t, "a263-aws-admin", "test"), "allowed_roles": []string{"reader"}, "role_bindings": map[string]string{"reader": "arn:aws:iam::000000000000:role/a263-reader"}, "max_ttl": "1h", "allow_insecure_loopback": true, "revoke_with_deny_policy": true, "gateway": map[string]any{"endpoint": stand.url, "service": "s3", "region": "us-east-1"}}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var provider config.DynamicSecretProviderConfig
	if json.Unmarshal(raw, &provider) != nil {
		t.Fatal("provider config fixture decode")
	}
	stsProvider := provider
	stsProvider.ID = "pam-aws-sts-provider"
	stsProvider.Gateway = &config.DynamicSecretGatewayConfig{Endpoint: endpoint, Service: "sts", Region: "us-east-1"}
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{provider, stsProvider}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := startGatewayFixture(t, gatewayFixtureOptions{aws: registry, maxTTL: time.Hour})
	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/targets", f.operator, "a263-aws-register", map[string]any{"id": "aws-api", "target_type": "aws", "provider_id": "pam-aws-provider", "allowed_roles": []string{"reader"}, "gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": f.gatewayAddr}); status != http.StatusCreated {
		t.Fatalf("register AWS gateway account = %d %s", status, body)
	}
	session := f.open("a263-aws", map[string]any{"target_type": "aws", "target_id": "aws-api", "role": "reader", "ttl_seconds": 900})
	if session.Gateway == nil || session.Delivery != "gateway" {
		t.Fatal("AWS session exposed credentials instead of a gateway ticket")
	}
	defer func() {
		_, _ = secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a263-aws-cleanup", map[string]any{"reason": "fixture complete"})
	}()
	out, stop := f.connect(session.ID, session.Gateway.Ticket, fixtureAWSCommand.MatchString)
	defer stop()
	otherID := uuid.NewString()
	registerServedTenantID(t, f.h.servedHarness, otherID, "A263 AWS other tenant")
	other := seedScopedTokenSubject(t, f.h.store, otherID, "other-reader", "access:read", "access:write")
	if status, _ := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID, other, nil); status != http.StatusNotFound {
		t.Fatal("another tenant read the AWS account session")
	}
	deniedReq := map[string]any{"target_type": "aws", "target_id": "aws-api", "role": "administrator", "ttl_seconds": 900, "reason": "negative scope proof", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine"))}
	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", f.requester, "a263-aws-denied-role", deniedReq); status != http.StatusUnprocessableEntity {
		t.Fatalf("unauthorized AWS role = %d %s", status, body)
	}
	wrong, err := mtls.GatewayDial(f.ctx, session.Gateway.Address, []byte(session.Gateway.CAPEM), session.Gateway.SPIFFEID)
	if err != nil {
		t.Fatal(err)
	}
	_ = wrong.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = io.WriteString(wrong, "TRSTCTL-GATEWAY/1 "+session.ID+" a263-wrong-ticket\n")
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(wrong).ReadString('\n')
	_ = wrong.Close()
	if err != nil || !strings.HasPrefix(line, "DENY ") {
		t.Fatal("wrong AWS gateway ticket admitted")
	}
	port := fixtureAWSCommand.FindStringSubmatch(out)[1]
	if !strings.Contains(out, "--region us-east-1 s3") {
		t.Fatal("CLI omitted the frozen reviewed signing scope")
	}

	result, err := a201Exec(target, "aws", "--no-sign-request", "--region", "us-east-1", "--endpoint-url", "http://host.docker.internal:"+port, "s3api", "get-object", "--bucket", "a263-gateway", "--key", "note", "/tmp/a263-client-note")
	if err != nil {
		t.Fatalf("stock AWS CLI without a credential: %v %s", err, result)
	}
	note, err := a201Exec(target, "cat", "/tmp/a263-client-note")
	if err != nil || strings.TrimSpace(note) != "a263-owned-note" {
		t.Fatal("stock AWS CLI did not read the owned target object")
	}
	if status := stand.probe(t, "/a263-gateway/note"); status != http.StatusOK {
		t.Fatalf("independent issued credential before revoke = %d", status)
	}
	if status := stand.probe(t, "/a263-gateway/forbidden"); status != http.StatusForbidden {
		t.Fatalf("role scope stand-in = %d", status)
	}
	if status := stand.probe(t, "/a263-gateway/note", true); status != http.StatusForbidden {
		t.Fatalf("corrupt issued signature = %d", status)
	}
	response, err := http.Get(stand.url + "/a263-gateway/note")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("direct unauthenticated target request admitted")
	}
	peer, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	_ = peer.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.WriteString(peer, "GET /a263-gateway/note HTTP/1.1\r\nHost: gateway\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	replies := bufio.NewReader(peer)
	live, err := http.ReadResponse(replies, nil)
	if err != nil || live.StatusCode != http.StatusOK {
		t.Fatalf("live API request = %v %v", live, err)
	}
	_, _ = io.Copy(io.Discard, live.Body)
	_ = live.Body.Close()
	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/terminate", f.operator, "a263-aws-terminate", map[string]any{"reason": "A263 native wire proof"}); status != http.StatusAccepted {
		t.Fatalf("terminate: %d %s", status, body)
	}
	if _, err := replies.ReadByte(); err == nil {
		t.Fatal("terminated cloud API connection remained open")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("cloud API termination did not close the connection")
	}
	a201Await(t, "exact AWS session denial published", stand.allDenied)
	a201Await(t, "AWS durable revocation completed", func() bool { state := f.sessionRead(session.ID); return state["status"] == "revoked" })
	if status := stand.probe(t, "/a263-gateway/note"); status != http.StatusForbidden {
		t.Fatalf("same issued credential after exact denial = %d", status)
	}
	a201Await(t, "AWS gateway recalled", func() bool {
		end, _ := f.sessionRead(session.ID)["gateway_end"].(map[string]any)
		return end != nil && end["ended"] == "recalled"
	})
	a201Await(t, "AWS recording sealed", func() bool {
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording", f.requester, nil)
		return status == http.StatusOK && strings.Contains(string(body), `"status":"sealed"`)
	})
	if status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording/verify", f.requester, nil); status != http.StatusOK || !strings.Contains(string(body), `"verified":true`) {
		t.Fatalf("AWS recording verify = %d %s", status, body)
	}
	_, read := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID, f.requester, nil)
	environment, err := exec.Command("docker", "exec", target, "sh", "-c", `printf '%s\000%s\000%s' "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$AWS_SESSION_TOKEN"`).Output() // #nosec G204 -- fixed command inspects only AWS variables in the test-owned CLI container (CWE-78)
	if err != nil {
		t.Fatal("owned CLI environment inspection failed")
	}
	stand.assertNoCredentialBytes(t, environment)
	secret.Wipe(environment)
	stand.assertNoCredential(t, out, result, string(read), f.gatewayLog.String(), recordingText(t, f.h, session.ID))

	// The second supported service uses the same held-STS credential path and
	// an actual native Query API request, rather than assuming S3 proves STS.
	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/targets", f.operator, "a263-aws-sts-register", map[string]any{"id": "aws-sts-api", "target_type": "aws", "provider_id": "pam-aws-sts-provider", "allowed_roles": []string{"reader"}, "gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": f.gatewayAddr}); status != http.StatusCreated {
		t.Fatalf("register STS API target = %d %s", status, body)
	}
	stsSession := f.open("a263-aws-sts", map[string]any{"target_type": "aws", "target_id": "aws-sts-api", "role": "reader", "ttl_seconds": 900})
	defer func() {
		_, _ = secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+stsSession.ID+"/revoke", f.requester, "a263-aws-sts-cleanup", map[string]any{"reason": "fixture complete"})
	}()
	stsOut, stopSTS := f.connect(stsSession.ID, stsSession.Gateway.Ticket, fixtureAWSCommand.MatchString)
	defer stopSTS()
	if !strings.Contains(stsOut, "--region us-east-1 sts") {
		t.Fatal("STS CLI omitted its reviewed signing scope")
	}
	stsPort := fixtureAWSCommand.FindStringSubmatch(stsOut)[1]
	identity, err := a201Exec(target, "aws", "--no-sign-request", "--region", "us-east-1", "--endpoint-url", "http://host.docker.internal:"+stsPort, "sts", "get-caller-identity")
	if err != nil || !strings.Contains(identity, "assumed-role/a263-reader/") {
		t.Fatal("stock STS CLI did not authenticate as its issued role")
	}
	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+stsSession.ID+"/terminate", f.operator, "a263-aws-sts-terminate", map[string]any{"reason": "A263 STS proof"}); status != http.StatusAccepted {
		t.Fatalf("terminate STS API = %d %s", status, body)
	}
	a201Await(t, "STS API session revoked", func() bool { return f.sessionRead(stsSession.ID)["status"] == "revoked" })
	a201Await(t, "STS API recording sealed", func() bool {
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+stsSession.ID+"/recording", f.requester, nil)
		return status == http.StatusOK && strings.Contains(string(body), `"status":"sealed"`)
	})
	if status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+stsSession.ID+"/recording/verify", f.requester, nil); status != http.StatusOK || !strings.Contains(string(body), `"verified":true`) {
		t.Fatal("STS API recording did not verify")
	}
	stand.assertNoCredential(t, stsOut, identity, recordingText(t, f.h, stsSession.ID))

}
