// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/cli"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/objectstore/s3test"
)

// stallingObjectStore holds every recording chunk write until released, as
// an object store that stopped answering writes would.
type stallingObjectStore struct {
	objectstore.Store
	mu      sync.Mutex
	stalled bool
	release chan struct{}
	waiting atomic.Int64
}

func (s *stallingObjectStore) Create(ctx context.Context, name string, body io.ReadSeeker, size int64, sum []byte) error {
	s.mu.Lock()
	stalled, release := s.stalled, s.release
	s.mu.Unlock()
	if stalled && strings.Contains(name, "/recordings/") && !strings.HasSuffix(name, "manifest.json") {
		s.waiting.Add(1)
		defer s.waiting.Add(-1)
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.Store.Create(ctx, name, body, size, sum)
}

func (s *stallingObjectStore) unstall() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stalled {
		s.stalled = false
		close(s.release)
	}
}

// refusalCountingChannel counts the uploads the control plane refused as
// backpressure; the gateway retries them.
type refusalCountingChannel struct {
	*sshCollectionServedChannel
	refused atomic.Int64
}

func (c *refusalCountingChannel) UploadSessionRecording(ctx context.Context, id int64, attempt, seq int, chunk []byte, final bool) error {
	err := c.sshCollectionServedChannel.UploadSessionRecording(ctx, id, attempt, seq, chunk, final)
	if status.Code(err) == codes.ResourceExhausted {
		c.refused.Add(1)
	}
	return err
}

// TestServedStalledObjectStoreAppliesBackpressureA278 is A278 part 3's
// Done-when: a stalled object store applies backpressure with no data loss
// and without stalling the gateway. A recorded PostgreSQL session runs
// through the gateway while the object store holds every chunk write. Uploads
// return at once into staging, which stays within its bound; past it they are
// refused as retryable and the gateway keeps and retries them; meanwhile the
// gateway's agent channel still answers its heartbeat promptly and the
// recording is not sealed. Once the store answers again, every staged chunk
// is stored in order, the ended session's recording is sealed with its final
// chunk and verifies, and every one of the session's statements is in it.
func TestServedStalledObjectStoreAppliesBackpressureA278(t *testing.T) {
	if testing.Short() {
		t.Skip("starts PostgreSQL")
	}
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminDSNRef := pamPostgresAdminFileRef(t, pgDSN)
	objects := &stallingObjectStore{Store: s3test.NewServer(t).Open(t), release: make(chan struct{})}
	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gatewayAddr := raw.Addr().String()
	const staging = 48 << 10
	h := newRoleHarnessNamedWithEventOptions(t, "a278b-gw", []string{mtls.AgentRoleGateway}, []string{relay.KindAccessGatewaySession}, nil, func(d *Deps) {
		wirePAMPostgresProvider(d, adminDSNRef, 5*time.Minute)
		d.PAM = PAMConfig{Enabled: true, DefaultTTL: time.Minute, MaxTTL: 3 * time.Minute, ExpiryInterval: 50 * time.Millisecond,
			RecordingStagingBytes: staging, Attestors: []attest.Attestor{servedPAMAttestor{}}}
		d.ArchiveObjectStore = objects
		d.AuditSigningKey = auditKey
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Cleanup(objects.unstall)
	startServedExternalCADispatcher(t, h.servedHarness)
	go h.srv.RunPAMSessionExpiry(ctx)
	gatewayID := agentRowID(h.tenant, h.agent)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: gatewayID, Version: "a278", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	operator := seedScopedTokenSubject(t, h.store, h.tenant, "a278b-operator", "access:read", "access:targets.write")
	requester := seedScopedTokenSubject(t, h.store, h.tenant, "a278b-requester", "access:read", "access:write")
	reviewerOne := seedScopedTokenSubject(t, h.store, h.tenant, "a278b-reviewer-1", "access:approve")
	reviewerTwo := seedScopedTokenSubject(t, h.store, h.tenant, "a278b-reviewer-2", "access:approve")
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/targets", operator, "a278b-target", map[string]any{
		"id": "pg-stall", "target_type": "postgres", "provider_id": "pam-pg-provider", "allowed_roles": []string{"readonly"},
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
	channel := &refusalCountingChannel{sshCollectionServedChannel: &sshCollectionServedChannel{t: t, h: h}}
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

	session := servedPAMReviewedOpen(t, h.servedHarness, requester, reviewerOne, reviewerTwo, "a278b-open", map[string]any{
		"target_type": "postgres", "target_id": "pg-stall", "role": "readonly", "ttl_seconds": 150, "reason": "CHG-278 backpressure proof",
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

	// The object store stops answering writes; the session keeps working.
	objects.mu.Lock()
	objects.stalled = true
	objects.mu.Unlock()
	pad := strings.Repeat("x", 1500)
	const statements = 160
	queries := make(chan error, 1)
	go func() {
		for i := range statements {
			if r := client.ExecParams(ctx, fmt.Sprintf("SELECT 'a278-marker-%03d-%s' AS note", i, pad), nil, nil, nil, nil).Read(); r.Err != nil {
				queries <- r.Err
				return
			}
		}
		queries <- nil
	}()
	staged := func() (rows int, bytes int64) {
		t.Helper()
		_ = h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*), COALESCE(sum(octet_length(sealed)), 0) FROM pam_recording_uploads WHERE session_id = $1::uuid`, session.ID).Scan(&rows, &bytes)
		})
		return rows, bytes
	}
	a201Await(t, "uploads pushed back while the store is stalled", func() bool { return channel.refused.Load() > 0 })
	rows, stagedBytes := staged()
	if rows == 0 || stagedBytes > staging+(512<<10) {
		t.Fatalf("staging while stalled: %d chunks, %d bytes (bound %d plus one chunk)", rows, stagedBytes, staging)
	}
	// The gateway is not stalled: its agent channel answers at once.
	started := time.Now()
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: gatewayID, Version: "a278", Status: "active"}); err != nil || time.Since(started) > 2*time.Second {
		t.Fatalf("the gateway's heartbeat while the store is stalled: %v after %s", err, time.Since(started))
	}
	if status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording", requester, nil); status == http.StatusOK && strings.Contains(string(body), `"status":"sealed"`) {
		t.Fatalf("the recording sealed while chunks were waiting: %s", body)
	}

	// The store answers again: nothing was lost.
	objects.unstall()
	select {
	case err := <-queries:
		if err != nil {
			t.Fatalf("a statement through the gateway failed: %v", err)
		}
	case <-time.After(90 * time.Second):
		t.Fatal("the session's statements did not finish after the store recovered")
	}
	_ = client.Close(ctx)
	stopTunnel()
	<-tunnelDone
	if status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/access/sessions/"+session.ID+"/revoke", requester,
		"a278b-end", map[string]any{"reason": "the work is done"}); status != http.StatusAccepted {
		t.Fatalf("end the session = %d %s", status, body)
	}
	a201Await(t, "the recording is sealed after the store recovers", func() bool {
		status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording", requester, nil)
		var rec struct {
			Status        string `json:"status"`
			FinalReceived bool   `json:"final_received"`
		}
		return status == http.StatusOK && json.Unmarshal(body, &rec) == nil && rec.Status == "sealed" && rec.FinalReceived
	})
	if rows, _ := staged(); rows != 0 {
		t.Fatalf("%d chunks still staged after the seal", rows)
	}
	if status, body := secretsReq(t, h.servedHarness, http.MethodGet, "/api/v1/access/sessions/"+session.ID+"/recording/verify", requester, nil); status != http.StatusOK || !strings.Contains(string(body), `"verified":true`) {
		t.Fatalf("verify the recording = %d %s", status, body)
	}
	text := recordingText(t, h, session.ID)
	for i := range statements {
		if marker := fmt.Sprintf("a278-marker-%03d-", i); !strings.Contains(text, marker) {
			t.Fatalf("the recording lost statement %d (%s)", i, marker)
		}
	}
	if objects.waiting.Load() != 0 {
		t.Fatalf("%d chunk writes still waiting", objects.waiting.Load())
	}
}
