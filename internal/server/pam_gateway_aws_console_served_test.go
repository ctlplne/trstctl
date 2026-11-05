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
	"strconv"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Native federation/login is a strict stand-in; STS/IAM wire calls use LocalStack.
func TestServedGatewayAWSConsoleHandoffA263(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if out, err := exec.Command("docker", "image", "inspect", a202LocalStackImage).CombinedOutput(); err != nil {
		t.Skipf("approved LocalStack image unavailable: %v %s", err, out)
	} // #nosec G204 -- fixed local tool and already-approved fixture image (CWE-78)
	target, address := a201Container(t, "4566", "-e", "SERVICES=iam,sts", a202LocalStackImage)
	endpoint := "http://" + address
	a201Await(t, "AWS console lab IAM/STS", func() bool {
		response, err := http.Get(endpoint + "/_localstack/health")
		if err != nil {
			return false
		}
		defer func() { _ = response.Body.Close() }()
		var health struct{ Services map[string]string }
		if json.NewDecoder(response.Body).Decode(&health) != nil {
			return false
		}
		for _, service := range []string{"iam", "sts"} {
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
	native("iam", "create-role", "--role-name", "a263-console-reader", "--assume-role-policy-document", trust)
	native("iam", "put-role-policy", "--role-name", "a263-console-reader", "--policy-name", "console-read", "--policy-document", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}`)
	stand := newA263AWSStandIn(t, endpoint)
	federation := newA263ConsoleStandIn(t, stand)
	wire := map[string]any{"tenant_id": servedTestTenant, "id": "pam-aws-provider", "type": "aws-sts", "endpoint": stand.url, "iam_endpoint": stand.url, "region": "us-east-1", "access_key_id": "test", "secret_access_key_ref": writeServedCredentialFile(t, "a263-console-admin", "test"), "allowed_roles": []string{"reader"}, "role_bindings": map[string]string{"reader": "arn:aws:iam::000000000000:role/a263-console-reader"}, "max_ttl": "1h", "allow_insecure_loopback": true, "revoke_with_deny_policy": true, "gateway": map[string]any{"endpoint": endpoint, "service": "sts", "region": "us-east-1"}, "console": map[string]any{"federation_endpoint": federation.url + "/federation", "destination": federation.url + "/console"}}
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
	f := startGatewayFixture(t, gatewayFixtureOptions{aws: registry, maxTTL: time.Hour})
	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/targets", f.operator, "a263-console-register", map[string]any{"id": "aws-console", "target_type": "aws-console", "provider_id": "pam-aws-provider", "allowed_roles": []string{"reader"}, "gateway_agent_id": agentRowID(servedTestTenant, "role-agent"), "gateway_address": f.gatewayAddr}); status != http.StatusCreated {
		t.Fatalf("register native AWS console account = %d %s", status, strings.TrimSpace(string(body)))
	}
	session := f.open("a263-console", map[string]any{"target_type": "aws-console", "target_id": "aws-console", "role": "reader", "ttl_seconds": 900})
	if session.Gateway == nil || session.Delivery != "gateway" {
		t.Fatal("native console lease escaped gateway custody")
	}
	defer func() {
		_, _ = secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", f.requester, "a263-console-cleanup", map[string]any{"reason": "fixture complete"})
	}()
	otherID := uuid.NewString()
	registerServedTenantID(t, f.h.servedHarness, otherID, "A263 console other tenant")
	other := seedScopedTokenSubject(t, f.h.store, otherID, "other-reader", "access:read", "access:write")
	if status, _ := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID, other, nil); status != http.StatusNotFound {
		t.Fatal("another tenant read console access")
	}
	deniedRequest := map[string]any{"request_id": uuid.NewString(), "target_type": "aws-console", "target_id": "aws-console", "role": "administrator", "ttl_seconds": 900, "reason": "negative role proof", "method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine"))}
	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", f.requester, "a263-console-denied-role", deniedRequest); status != http.StatusUnprocessableEntity || !bytes.Contains(body, []byte("is not allowed")) {
		t.Fatal("unapproved console role admitted")
	}
	refusedTicket := func(ticket string) {
		t.Helper()
		conn, err := mtls.GatewayDial(f.ctx, session.Gateway.Address, []byte(session.Gateway.CAPEM), session.Gateway.SPIFFEID)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, err = io.WriteString(conn, "TRSTCTL-GATEWAY/1 "+session.ID+" "+ticket+"\n")
		if err != nil {
			t.Fatal(err)
		}
		line, err := bufio.NewReader(conn).ReadString('\n')
		_ = conn.Close()
		if err != nil || !strings.HasPrefix(line, "DENY ") {
			t.Fatal("refused console gateway ticket admitted")
		}
	}
	refusedTicket("a263-wrong-ticket")
	status, templateBody := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/templates", f.operator, "a263-console-recording-template", map[string]any{"name": "recorded-console-requirement", "reason": "Full capture required", "required_approvals": 2, "max_ttl_seconds": 900, "require_recording": true})
	var template api.PAMAccessTemplate
	if status != http.StatusCreated || json.Unmarshal(templateBody, &template) != nil {
		t.Fatalf("full-recording policy fixture = %d %s", status, templateBody)
	}
	deniedRequest["request_id"] = uuid.NewString()
	deniedRequest["role"] = "reader"
	deniedRequest["template_id"] = template.ID
	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/session-requests", f.requester, "a263-console-recording-refused", deniedRequest); status != http.StatusUnprocessableEntity || !bytes.Contains(body, []byte("requires a recorded gateway session")) {
		t.Fatalf("full-recording console refusal = %d %s", status, body)
	}

	command := regexp.MustCompile(`Open http://127\.0\.0\.1:(\d+)/ in your browser`)
	out, stop := f.connect(session.ID, session.Gateway.Ticket, command.MatchString)
	defer stop()
	local := "127.0.0.1:" + command.FindStringSubmatch(out)[1]
	home := t.TempDir()
	curl := func(destination string, input []byte, headers ...string) (int, []byte) {
		t.Helper()
		args := []string{"-sS", "--write-out", "\n%{http_code}", destination}
		if input != nil {
			args = append(args, "--data-binary", "@-", "-H", "Content-Type: application/x-www-form-urlencoded; charset=UTF-8")
		}
		for _, header := range headers {
			args = append(args, "-H", header)
		}
		cmd := exec.CommandContext(f.ctx, "curl", args...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "TMPDIR=" + home}
		cmd.Stdin = bytes.NewReader(input)
		raw, err := cmd.CombinedOutput()
		if err != nil {
			secret.Wipe(raw)
			redacted := regexp.MustCompile(`[A-Za-z0-9_+/=-]{12,}`).ReplaceAllString(f.gatewayLog.String(), "[redacted]")
			t.Fatalf("stock console HTTP client: %v; gateway: %s", err, redacted)
		}
		split := bytes.LastIndexByte(raw, '\n')
		if split < 0 {
			secret.Wipe(raw)
			t.Fatal("console client status missing")
		}
		status, err := strconv.Atoi(string(raw[split+1:]))
		if err != nil {
			secret.Wipe(raw)
			t.Fatal(err)
		}
		return status, raw[:split]
	} // #nosec G204 G702 -- stock curl is confined to owned loopback gateway/federation fixtures; private body travels on stdin (CWE-78)
	status, landing := curl("http://"+local+"/", nil)
	defer secret.Wipe(landing)
	if status != http.StatusOK || !bytes.Contains(landing, []byte("Open the native AWS console")) {
		t.Fatal("native console review page unavailable")
	}
	if m, _ := federation.counts(); m != 0 {
		t.Fatal("GET review minted a native token")
	}
	field := func(body []byte, name string) []byte {
		t.Helper()
		pattern := regexp.MustCompile(`name="` + name + `" value="([^"]*)"`)
		parts := pattern.FindSubmatch(body)
		if len(parts) != 2 {
			t.Fatal("native console form field missing")
		}
		return bytes.Clone(parts[1])
	}
	proof := field(landing, "proof")
	defer secret.Wipe(proof)
	form := append([]byte("proof="), proof...)
	form = append(form, []byte("&idempotency_key=")...)
	form = append(form, proof...)
	defer secret.Wipe(form)
	status, refused := curl("http://"+local+"/handoff", form, "Origin: https://foreign.example")
	secret.Wipe(refused)
	if status != http.StatusForbidden {
		t.Fatal("foreign origin minted a console handoff")
	}
	forged := []byte("proof=forged&idempotency_key=forged")
	status, refused = curl("http://"+local+"/handoff", forged, "Origin: http://"+local)
	secret.Wipe(refused)
	if status != http.StatusForbidden {
		t.Fatal("forged review proof admitted")
	}
	if m, _ := federation.counts(); m != 0 {
		t.Fatal("refused browser request reached native mint")
	}
	status, conflict := curl("http://"+local+"/handoff", form, "Origin: http://"+local, "Idempotency-Key: mismatched")
	secret.Wipe(conflict)
	if status != http.StatusConflict {
		t.Fatal("conflicting console idempotency key admitted")
	}
	status, rebound := curl("http://"+local+"/handoff", form, "Host: 127.0.0.1.evil.example:8000", "Origin: http://127.0.0.1.evil.example:8000")
	secret.Wipe(rebound)
	if status != http.StatusForbidden {
		t.Fatal("rebound console origin admitted")
	}

	status, page := curl("http://"+local+"/handoff", form, "Origin: http://"+local)
	defer secret.Wipe(page)
	if status != http.StatusOK || !bytes.Contains(page, []byte("AWS sign-in handoff")) {
		t.Fatal("native sign-in handoff failed")
	}
	status, replay := curl("http://"+local+"/handoff", form, "Origin: http://"+local)
	defer secret.Wipe(replay)
	if status != http.StatusOK || !bytes.Equal(page, replay) {
		t.Fatal("replayed console mutation did not return its original result")
	}
	if m, _ := federation.counts(); m != 1 {
		t.Fatal("native mint repeated under replay")
	}
	nativeToken := field(page, "SigninToken")
	defer secret.Wipe(nativeToken)
	nativeForm := []byte("Action=login&Issuer=http%3A%2F%2F" + local + "%2F&Destination=" + strings.ReplaceAll(strings.ReplaceAll(federation.url+"/console", ":", "%3A"), "/", "%2F") + "&SigninToken=")
	nativeForm = append(nativeForm, nativeToken...)
	defer secret.Wipe(nativeForm)
	status, result := curl(federation.url+"/federation", nativeForm)
	defer secret.Wipe(result)
	if status != http.StatusOK || !bytes.Contains(result, []byte("accepted the issued role")) {
		t.Fatal("native console stand-in did not accept the issued role")
	}
	if _, logins := federation.counts(); logins != 1 {
		t.Fatal("native console login was not observed")
	}
	stand.assertNoCredentialBytes(t, landing, page, replay, []byte(out), result)
	peer, err := net.Dial("tcp", local)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	_ = peer.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.WriteString(peer, "GET / HTTP/1.1\r\nHost: "+local+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reply := bufio.NewReader(peer)
	live, err := http.ReadResponse(reply, nil)
	if err != nil || live.StatusCode != http.StatusOK {
		t.Fatal("live native console gateway failed")
	}
	_, _ = io.Copy(io.Discard, live.Body)
	_ = live.Body.Close()
	if status, body := secretsReqKey(t, f.h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/terminate", f.operator, "a263-console-terminate", map[string]any{"reason": "native handoff proof"}); status != http.StatusAccepted {
		t.Fatalf("console terminate = %d %s", status, body)
	}
	if _, err := reply.ReadByte(); err == nil {
		t.Fatal("terminated console gateway connection remained open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("console recall did not close the connection")
	}
	refusedTicket(session.Gateway.Ticket)
	a201Await(t, "exact issued role denial", stand.allDenied)
	status, deniedLogin := curl(federation.url+"/federation", nativeForm)
	secret.Wipe(deniedLogin)
	if status != http.StatusForbidden {
		t.Fatal("denied issued role still admitted by native-login stand-in")
	}
	a201Await(t, "native handoff recording sealed", func() bool {
		status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording", f.requester, nil)
		return status == http.StatusOK && strings.Contains(string(body), `"status":"sealed"`) && strings.Contains(string(body), `"scope":"native_console_handoff"`)
	})
	if status, body := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording/verify", f.requester, nil); status != http.StatusOK || !bytes.Contains(body, []byte(`"verified":true`)) || !bytes.Contains(body, []byte(`"scope":"native_console_handoff"`)) {
		t.Fatal("handoff-only recording scope did not verify")
	}
	recording := []byte(recordingText(t, f.h, session.ID))
	defer secret.Wipe(recording)
	stand.assertNoCredentialBytes(t, recording, []byte(f.gatewayLog.String()))
	federation.assertTokenAbsent(t, recording)
	federation.assertTokenAbsent(t, []byte(f.gatewayLog.String()))
	if !bytes.Contains(recording, []byte("native activity is outside gateway capture")) {
		t.Fatal("recording implied captured native console activity")
	}

	status, exportBody := secretsReq(t, f.h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording/export", f.auditor, nil)
	var exported api.PAMRecordingExport
	if status != http.StatusOK || json.Unmarshal(exportBody, &exported) != nil {
		t.Fatal("handoff evidence export unavailable")
	}
	signed, err := f.auditKey.JWKS().VerifyArtifact(exported.ManifestSignature, recordingManifestArtifact)
	if err != nil || !bytes.Equal(signed, exported.Manifest) {
		t.Fatal("offline handoff signature failed")
	}
	var manifest recordingManifest
	if json.Unmarshal(signed, &manifest) != nil || manifest.Scope != "native_console_handoff" {
		t.Fatal("offline signed artifact omitted its handoff-only scope")
	}
	manifest.Scope = ""
	changed, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(changed, signed) {
		t.Fatal("recording scope was not covered by the signature")
	}
	federation.assertTokenAbsent(t, exportBody)
	stand.assertNoCredentialBytes(t, exportBody)
	files, err := os.OpenRoot(home)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = files.Close() }()
	if err := filepath.WalkDir(home, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(home, path)
		if err != nil {
			return err
		}
		data, err := files.ReadFile(relative)
		defer secret.Wipe(data)
		if err != nil {
			return err
		}
		stand.assertNoCredentialBytes(t, data)
		federation.assertTokenAbsent(t, data)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

}
