// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/objectstore/s3test"
)

// UploadSessionRecording lets the served gateway upload recordings over the
// same channel it claims on.
func (c *sshCollectionServedChannel) UploadSessionRecording(ctx context.Context, id int64, attempt, seq int, chunk []byte, final bool) error {
	response, err := c.h.client.UploadSessionRecording(ctx, &transport.UploadSessionRecordingRequest{JobID: id, Attempt: attempt, Seq: seq, Chunk: chunk, Final: final})
	if err != nil {
		return err
	}
	if response.Stopped || !response.Accepted {
		return accessgateway.ErrRecordingStopped
	}
	return nil
}

// TestServedGatewayRecordsMaskedSealedSessionsA255 records an SSH session
// (shell, exec and SFTP) and a PostgreSQL session through the gateway:
// secrets are masked before anything leaves the gateway, SFTP is recorded as
// operations without file contents, each chunk is sealed for the tenant in the
// object store and chained, the recording closes with a manifest signed by
// the audit key, verification passes, and a modified chunk or manifest fails
// it.
func TestServedGatewayRecordsMaskedSealedSessionsA255(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	for _, tool := range []string{"ssh", "sftp"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("the stock %s client is required: %v", tool, err)
		}
	}
	token := "ghp_" + strings.Repeat("R", 36)
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	objects := s3test.NewServer(t)
	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gatewayAddr := raw.Addr().String()
	gatewayID := agentRowID(servedTestTenant, "role-agent")
	h := newRoleHarnessWithDeps(t, []string{mtls.AgentRoleGateway}, []string{relay.KindAccessGatewaySession}, func(d *Deps) {
		d.Protocols.SSH = config.ProtocolToggle{Enabled: true, TenantID: servedTestTenant}
		wirePAMPostgresProvider(d, adminDSNRef, time.Minute)
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: 50 * time.Millisecond,
			Attestors: []attest.Attestor{servedPAMAttestor{}},
			PostgresTargets: []PAMPostgresTarget{{TenantID: servedTestTenant, ID: "pg-rec", ProviderID: "pam-pg-provider",
				AllowedRoles: []string{"readonly"}, GatewayAgentID: gatewayID, GatewayAddress: gatewayAddr}}}
		d.ArchiveObjectStore = objects.Open(t)
		d.AuditSigningKey = auditKey
	})
	if _, err := h.client.Heartbeat(context.Background(), &transport.HeartbeatRequest{AgentID: h.agent, Version: "a255", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startServedExternalCADispatcher(t, h.servedHarness)
	go h.srv.RunPAMSessionExpiry(ctx)

	caPub, err := h.srv.protocols.ssh.AuthorityKey()
	if err != nil {
		t.Fatal(err)
	}
	sshd := startPAMSSHD(t, caPub)
	var pins []string
	for _, keyType := range []string{"ed25519", "ecdsa", "rsa"} {
		out, err := pamDockerOutput(t, 15*time.Second, "exec", sshd.Name, "ssh-keygen", "-lf", "/etc/ssh/ssh_host_"+keyType+"_key.pub")
		fields := strings.Fields(string(out))
		if err != nil || len(fields) < 2 {
			t.Fatalf("host key fingerprint: %v %s", err, out)
		}
		pins = append(pins, fields[1])
	}
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "pam-operator", "access:read", "access:targets.write")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "pam-requester", "access:read", "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-one", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "pam-reviewer-two", "access:approve")
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", operator, "a255-target", map[string]any{
		"id": "ssh-rec", "target_type": "ssh", "host": "127.0.0.1", "port": sshd.Port, "principals": []string{"alice"},
		"gateway_agent_id": gatewayID, "gateway_address": gatewayAddr, "host_key_fingerprints": pins}); status != http.StatusCreated {
		t.Fatalf("register target = %d %s", status, body)
	}
	cert, err := mtls.NewRenewingServerCertificate(h.srv.AgentCACertPEM(), []string{"127.0.0.1"}, func(csr []byte) ([]byte, error) {
		resp, err := h.client.SignGatewayServerCertificate(context.Background(), &transport.SignGatewayServerCertificateRequest{CSRDER: csr, Hosts: []string{"127.0.0.1"}})
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(resp.CertificatePEM)
		if block == nil {
			return nil, fmt.Errorf("not PEM")
		}
		return block.Bytes, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cert.Close)
	ln, err := mtls.GatewayWrapListener(raw, cert)
	if err != nil {
		t.Fatal(err)
	}
	var gatewayLog lockedBuffer
	gw, err := accessgateway.New(accessgateway.Config{Channel: &sshCollectionServedChannel{t: t, h: h}, Listener: ln,
		ClaimInterval: 100 * time.Millisecond, ExtendInterval: 200 * time.Millisecond,
		Logf: func(format string, args ...any) {
			_, _ = gatewayLog.Write([]byte(strings.TrimSpace(fmt.Sprintf(format, args...)) + "\n"))
		}})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gw.Run(ctx) }()

	api := httptest.NewServer(h.srv.Handler())
	defer api.Close()
	dir := t.TempDir()
	connect := func(sessionID, ticket string, wait func(string) bool) (string, func()) {
		t.Helper()
		ticketFile := filepath.Join(dir, sessionID+".ticket")
		if err := os.WriteFile(ticketFile, []byte(ticket+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var out lockedBuffer
		cctx, ccancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			cli.Run(cctx, []string{"access", "sessions", "connect", sessionID, "--ticket-file", ticketFile, "--listen", "127.0.0.1:0"},
				cli.Env{Server: api.URL, Token: requester, Tenant: h.tenant, HTTPClient: api.Client()}, strings.NewReader(""), &out, &out)
		}()
		for start := time.Now(); !wait(out.String()); time.Sleep(100 * time.Millisecond) {
			select {
			case <-done:
				t.Fatalf("CLI connect exited: %s (gateway: %s)", out.String(), gatewayLog.String())
			default:
			}
			if time.Since(start) > 30*time.Second {
				t.Fatalf("CLI tunnel not ready: %s", out.String())
			}
		}
		return out.String(), func() { ccancel(); <-done }
	}
	open := func(key string, req map[string]any) servedPAMSessionResponse {
		req["reason"], req["method"] = "a255 recording proof", "stub_pam"
		req["payload_base64"] = base64.StdEncoding.EncodeToString([]byte("genuine"))
		return servedPAMReviewedOpen(t, h.servedHarness, requester, reviewerOne, reviewerTwo, key, req)
	}

	// SSH: a shell command that prints a token, then SFTP up and down.
	sshSession := open("a255-ssh", map[string]any{"target_type": "ssh", "target_id": "ssh-rec", "role": "user", "ssh_principal": "alice", "ttl_seconds": 120})
	sshCmd := regexp.MustCompile(`ssh -p (\d+) -o UserKnownHostsFile=(\S+) `)
	cliOut, stopSSH := connect(sshSession.ID, sshSession.Gateway.Ticket, func(s string) bool { return sshCmd.MatchString(s) })
	m := sshCmd.FindStringSubmatch(cliOut)
	common := []string{"-F", "/dev/null", "-o", "IdentitiesOnly=yes", "-o", "IdentityFile=/dev/null", "-o", "IdentityAgent=none",
		"-o", "BatchMode=yes", "-o", "UserKnownHostsFile=" + m[2], "-o", "StrictHostKeyChecking=yes"}
	out, err := exec.CommandContext(ctx, "ssh", append(append(append([]string{}, common...), "-p", m[1], "client@127.0.0.1"), "echo leaked="+token+"; id -un")...).CombinedOutput() // #nosec G204 -- the stock ssh client against the test's own tunnel (CWE-78)
	if err != nil || !strings.Contains(string(out), "alice") {
		t.Fatalf("ssh through the gateway = %q, %v (gateway: %s)", out, err, gatewayLog.String())
	}
	upload := filepath.Join(dir, "upload.txt")
	if err := os.WriteFile(upload, []byte("file contents that are never recorded "+token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	batch := filepath.Join(dir, "sftp.batch")
	if err := os.WriteFile(batch, []byte("put "+upload+" /home/alice/uploaded.txt\nget /etc/hostname "+filepath.Join(dir, "hostname")+"\nrm /etc/passwd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(ctx, "sftp", append(append([]string{}, common...), "-P", m[1], "-b", batch, "client@127.0.0.1")...).CombinedOutput(); err == nil || !strings.Contains(string(out), "Permission denied") { // #nosec G204 -- the stock sftp client against the test's own tunnel (CWE-78)
		// The batch's last line is refused by the target, which ends the
		// batch with an error after the put and get succeeded.
		t.Fatalf("sftp through the gateway = %q, %v", out, err)
	}
	stopSSH()

	// PostgreSQL: a query carrying the token, and its bounded result.
	pgSession := open("a255-pg", map[string]any{"target_type": "postgres", "target_id": "pg-rec", "role": "readonly", "ttl_seconds": 50})
	pgListen := regexp.MustCompile(`connect your client to (127\.0\.0\.1:\d+)`)
	cliOut, stopPGTunnel := connect(pgSession.ID, pgSession.Gateway.Ticket, func(s string) bool { return pgListen.MatchString(s) })
	local := pgListen.FindStringSubmatch(cliOut)[1]
	pgCtx, pgCancel := context.WithTimeout(ctx, 30*time.Second)
	conn, err := pgconn.Connect(pgCtx, "postgres://client@"+local+"/postgres?sslmode=disable")
	pgCancel()
	if err != nil {
		t.Fatalf("psql through the gateway: %v (gateway: %s)", err, gatewayLog.String())
	}
	if r := conn.ExecParams(ctx, "SELECT current_user, '"+token+"' AS note FROM generate_series(1, 25)", nil, nil, nil, nil).Read(); r.Err != nil {
		t.Fatalf("query through the gateway: %v", r.Err)
	}
	_ = conn.Close(ctx)
	stopPGTunnel()

	// Both sessions end; each recording is sealed with its final chunk.
	for _, id := range []string{sshSession.ID, pgSession.ID} {
		if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+id+"/revoke", requester,
			"a255-revoke-"+id, map[string]any{"reason": "a255 proof"}); status != http.StatusAccepted {
			t.Fatalf("revoke %s = %d %s", id, status, body)
		}
	}
	var recs = map[string]struct {
		Status        string `json:"status"`
		Chunks        int    `json:"chunks"`
		FinalReceived bool   `json:"final_received"`
	}{}
	for _, id := range []string{sshSession.ID, pgSession.ID} {
		a201Await(t, "the recording of "+id+" is sealed", func() bool {
			status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+id+"/recording", requester, nil)
			if status != http.StatusOK {
				return false
			}
			var rec struct {
				Status        string `json:"status"`
				Chunks        int    `json:"chunks"`
				FinalReceived bool   `json:"final_received"`
			}
			_ = json.Unmarshal(body, &rec)
			recs[id] = rec
			return rec.Status == "sealed"
		})
		if rec := recs[id]; rec.Chunks == 0 || !rec.FinalReceived {
			t.Fatalf("recording of %s = %+v", id, rec)
		}
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+id+"/recording/verify", requester, nil)
		if status != http.StatusOK || !strings.Contains(string(body), `"verified":true`) {
			t.Fatalf("verify %s = %d %s", id, status, body)
		}
	}

	// What was stored: sealed objects only; opened, masked frames.
	for _, key := range objects.Keys() {
		data, _ := objects.Object(key)
		if bytes.Contains(data, []byte(token)) || bytes.Contains(data, []byte("never recorded")) {
			t.Fatalf("object %s holds plaintext session content", key)
		}
	}
	sshText := recordingText(t, h, sshSession.ID)
	pgText := recordingText(t, h, pgSession.ID)
	for name, text := range map[string]string{"ssh": sshText, "postgres": pgText} {
		if strings.Contains(text, token) || strings.Contains(text, "never recorded") {
			t.Fatalf("the %s recording kept a secret or file contents:\n%s", name, text)
		}
		if !strings.Contains(text, "[masked:github-token]") {
			t.Fatalf("the %s recording shows no masked token:\n%s", name, text)
		}
	}
	for _, want := range []string{"exec: echo leaked=[masked:github-token]; id -un", "alice", `"op":"write","path":"/home/alice/uploaded.txt"`,
		`"op":"read","path":"/etc/hostname"`, `"op":"remove","path":"/etc/passwd"`, "permission_denied"} {
		if !strings.Contains(sshText, want) {
			t.Fatalf("ssh recording lacks %q:\n%s", want, sshText)
		}
	}
	// pgconn speaks the extended protocol: the statement is an unnamed
	// prepare.
	for _, want := range []string{"prepare: SELECT current_user, '[masked:github-token]' AS note", "columns: current_user, note",
		"truncated: further rows are not recorded", "complete: SELECT 25"} {
		if !strings.Contains(pgText, want) {
			t.Fatalf("postgres recording lacks %q:\n%s", want, pgText)
		}
	}

	// Tampering is found: a modified chunk, then a modified manifest.
	var chunkKey, manifestKey string
	for _, key := range objects.Keys() {
		switch {
		case strings.Contains(key, "recordings/"+sshSession.ID+"/0-"):
			chunkKey = key
		case strings.Contains(key, "recordings/"+pgSession.ID+"/manifest.json"):
			manifestKey = key
		}
	}
	original, _ := objects.Object(chunkKey)
	objects.Replace(chunkKey, append(append([]byte(nil), original[:len(original)-1]...), original[len(original)-1]^1))
	if _, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+sshSession.ID+"/recording/verify", requester, nil); !strings.Contains(string(body), "chunk 0 was modified") {
		t.Fatalf("a modified chunk verified: %s", body)
	}
	manifest, _ := objects.Object(manifestKey)
	objects.Replace(manifestKey, bytes.Replace(manifest, []byte(`"final_received":true`), []byte(`"final_received":false`), 1))
	if _, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+pgSession.ID+"/recording/verify", requester, nil); !strings.Contains(string(body), "the manifest object differs") {
		t.Fatalf("a modified manifest verified: %s", body)
	}
}

// recordingText opens a recording's chunks the way the control plane does
// and renders its frames as text for assertions.
func recordingText(t *testing.T, h *roleHarness, sessionID string) string {
	t.Helper()
	ctx := context.Background()
	chunks, err := h.store.ListPAMRecordingChunks(ctx, h.tenant, sessionID, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	for _, c := range chunks {
		view, err := objectstore.ForTenant(ctx, h.srv.pam.recordings.objects, h.tenant)
		if err != nil {
			t.Fatal(err)
		}
		var sealed bytes.Buffer
		if _, err := view.Get(ctx, recordingRel(view, c.ObjectRef), &sealed, recordingMaxChunk*2); err != nil {
			t.Fatal(err)
		}
		plain, err := openTenantValue(ctx, h.srv.pam.recordings.access, h.srv.pam.recordings.legacy, h.tenant, sealed.Bytes(),
			recordingAAD(h.tenant, sessionID, c.Ord, c.SHA256))
		if err != nil {
			t.Fatalf("open chunk %d: %v", c.Ord, err)
		}
		lines := bufio.NewScanner(bytes.NewReader(plain))
		lines.Buffer(make([]byte, 0, 1<<20), 4<<20)
		for lines.Scan() {
			var f struct {
				Stream string          `json:"s"`
				Data   string          `json:"d"`
				Event  string          `json:"e"`
				Kind   string          `json:"kind"`
				Text   string          `json:"v"`
				Op     json.RawMessage `json:"op"`
			}
			if err := json.Unmarshal(lines.Bytes(), &f); err != nil {
				t.Fatalf("frame %q: %v", lines.Bytes(), err)
			}
			switch {
			case f.Data != "":
				b, _ := base64.StdEncoding.DecodeString(f.Data)
				out.Write(b)
			case f.Event == "sftp":
				out.Write(f.Op)
				out.WriteString("\n")
			case f.Event != "":
				out.WriteString(f.Kind + ": " + f.Text + "\n")
			}
		}
	}
	return out.String()
}
