// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/objectstore/s3test"
	"trstctl.com/trstctl/internal/projections"
)

// dropFinalChannel is a gateway channel that loses the final chunk, as a
// gateway that dies (or loses the control plane) right after the last
// statement would: the recording never gets its final chunk.
type dropFinalChannel struct{ *sshCollectionServedChannel }

func (c *dropFinalChannel) UploadSessionRecording(ctx context.Context, id int64, attempt, seq int, chunk []byte, final bool) error {
	if final {
		return nil
	}
	return c.sshCollectionServedChannel.UploadSessionRecording(ctx, id, attempt, seq, chunk, final)
}

// TestVL141VerifyRecordingFlagsMissingFinalChunk: a recording sealed without
// its final chunk (final_received=false in the signed manifest) must not
// verify as a clean, complete recording.
func TestVL141VerifyRecordingFlagsMissingFinalChunk(t *testing.T) {
	if testing.Short() {
		t.Skip("starts PostgreSQL")
	}
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	objects := s3test.NewServer(t).Open(t)
	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gatewayAddr := raw.Addr().String()
	h := newRoleHarnessNamedWithEventOptions(t, "vl141-gw", []string{mtls.AgentRoleGateway}, []string{relay.KindAccessGatewaySession}, nil, func(d *Deps) {
		wirePAMPostgresProvider(d, adminDSNRef, 5*time.Minute)
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: 50 * time.Millisecond,
			Attestors: []attest.Attestor{servedPAMAttestor{}}}
		d.ArchiveObjectStore = objects
		d.AuditSigningKey = auditKey
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startServedExternalCADispatcher(t, h.servedHarness)
	go h.srv.RunPAMSessionExpiry(ctx)
	gatewayID := agentRowID(h.tenant, h.agent)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: gatewayID, Version: "vl141", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "vl141-operator", "access:read", "access:targets.write")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "vl141-requester", "access:read", "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "vl141-reviewer-1", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "vl141-reviewer-2", "access:approve")
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", operator, "vl141-target", map[string]any{
		"id": "pg-vl141", "target_type": "postgres", "provider_id": "pam-pg-provider", "allowed_roles": []string{"readonly"},
		"gateway_agent_id": gatewayID, "gateway_address": gatewayAddr}); status != http.StatusCreated {
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
	channel := &dropFinalChannel{&sshCollectionServedChannel{t: t, h: h}}
	var gatewayLog lockedBuffer
	gw, err := accessgateway.New(accessgateway.Config{Channel: channel, Listener: ln,
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

	session := servedPAMReviewedOpen(t, h.servedHarness, requester, reviewerOne, reviewerTwo, "vl141-open", map[string]any{
		"target_type": "postgres", "target_id": "pg-vl141", "role": "readonly", "ttl_seconds": 150, "reason": "CHG-141 final chunk proof",
		"method": "stub_pam", "payload_base64": base64.StdEncoding.EncodeToString([]byte("genuine"))})
	ticketFile := filepath.Join(t.TempDir(), "ticket")
	if err := os.WriteFile(ticketFile, []byte(session.Gateway.Ticket+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var cliOut lockedBuffer
	tunnelCtx, stopTunnel := context.WithCancel(ctx)
	tunnelDone := make(chan struct{})
	go func() {
		defer close(tunnelDone)
		cli.Run(tunnelCtx, []string{"access", "sessions", "connect", session.ID, "--ticket-file", ticketFile, "--listen", "127.0.0.1:0"},
			cli.Env{Server: api.URL, Token: requester, Tenant: h.tenant, HTTPClient: api.Client()}, strings.NewReader(""), &cliOut, &cliOut)
	}()
	listen := regexp.MustCompile(`connect your client to (127\.0\.0\.1:\d+)`)
	a201Await(t, "the tunnel", func() bool { return listen.MatchString(cliOut.String()) })
	pgCtx, pgCancel := context.WithTimeout(ctx, 30*time.Second)
	client, err := pgconn.Connect(pgCtx, "postgres://client@"+listen.FindStringSubmatch(cliOut.String())[1]+"/postgres?sslmode=disable")
	pgCancel()
	if err != nil {
		t.Fatalf("connect through the gateway: %v (gateway: %s)", err, gatewayLog.String())
	}
	for i := range 5 {
		if r := client.ExecParams(ctx, fmt.Sprintf("SELECT 'vl141-marker-%03d' AS note", i), nil, nil, nil, nil).Read(); r.Err != nil {
			t.Fatalf("statement %d: %v", i, r.Err)
		}
	}
	_ = client.Close(ctx)
	stopTunnel()
	<-tunnelDone
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", requester,
		"vl141-end", map[string]any{"reason": "the work is done"}); status != http.StatusAccepted {
		t.Fatalf("end the session = %d %s", status, body)
	}
	var rec struct {
		Status        string `json:"status"`
		Chunks        int    `json:"chunks"`
		FinalReceived bool   `json:"final_received"`
	}
	a201Await(t, "the recording is sealed without its final chunk", func() bool {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording", requester, nil)
		return status == http.StatusOK && json.Unmarshal(body, &rec) == nil && rec.Status == "sealed"
	})
	if rec.FinalReceived || rec.Chunks == 0 {
		t.Fatalf("setup: expected a sealed recording with chunks and final_received=false, got %+v", rec)
	}
	t.Logf("recording metadata: %+v", rec)
	status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording/verify", requester, nil)
	t.Logf("verify = %d %s", status, body)
	if status != http.StatusOK {
		t.Fatalf("verify = %d %s", status, body)
	}
	var verification struct {
		Verified bool     `json:"verified"`
		Problems []string `json:"problems"`
	}
	if err := json.Unmarshal(body, &verification); err != nil || verification.Verified || !strings.Contains(strings.Join(verification.Problems, " "), "final chunk") {
		t.Errorf("a recording sealed without its final chunk did not report failed verification: %s err=%v", body, err)
	}
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("pam-recording-sealed\x00"+h.tenant+"\x00"+session.ID)).String()
	sealedEvent, found, err := h.log.EventByID(ctx, eventID)
	if err != nil || !found || sealedEvent.Type != projections.EventPAMRecordingSealed {
		t.Fatalf("sealed event missing: found=%t type=%q err=%v", found, sealedEvent.Type, err)
	}
	var sealed struct {
		FinalReceived *bool `json:"final_received"`
	}
	if err := json.Unmarshal(sealedEvent.Data, &sealed); err != nil || sealed.FinalReceived == nil || *sealed.FinalReceived {
		t.Errorf("sealed event did not retain final_received=false: field=%v err=%v", sealed.FinalReceived, err)
	}
	var alert []byte
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT payload FROM outbox WHERE tenant_id=$1 AND destination='notification.risk' AND idempotency_key=$2`,
		h.tenant, "pam-recording-incomplete:"+session.ID).Scan(&alert); err != nil {
		t.Errorf("incomplete recording risk alert missing: %v", err)
	} else {
		var payload notify.Alert
		if err := json.Unmarshal(alert, &payload); err != nil || payload.Kind != notify.KindRecordingIncomplete || payload.SessionID != session.ID ||
			payload.RecordingPath != "/admin/access?session="+session.ID || payload.FinalReceived == nil || *payload.FinalReceived {
			t.Errorf("incomplete recording alert lacks session/final status: %+v err=%v", payload, err)
		} else if !strings.Contains(notify.FormatMessage(payload), "recording is incomplete") {
			t.Errorf("incomplete recording alert did not explain the gap: %s", notify.FormatMessage(payload))
		}
	}
}
