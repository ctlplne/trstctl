package projections_test

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/server"
	"trstctl.com/trstctl/internal/signing"
)

// staticSigner is a server.SignerProvider holding one client (a real signer
// child in these tests).
type staticSigner struct{ c *signing.Client }

func (s staticSigner) Client() *signing.Client { return s.c }

func buildSignerBin(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "trstctl-signer")
	out, err := exec.Command("go", "build", "-o", bin, "trstctl.com/trstctl/cmd/trstctl-signer").CombinedOutput()
	if err != nil {
		t.Fatalf("build trstctl-signer: %v\n%s", err, out)
	}
	return bin
}

// startSignerChild launches the real signer binary as a child and returns a
// provider plus a stop func — the genuine out-of-process AN-4 boundary.
func startSignerChild(t *testing.T) (server.SignerProvider, func()) {
	t.Helper()
	bin := buildSignerBin(t)
	dir, err := os.MkdirTemp("", "tp-")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")
	client, stop, err := signing.StartChild(context.Background(), bin, socket)
	if err != nil {
		t.Fatalf("StartChild: %v", err)
	}
	return staticSigner{client}, stop
}

func req(t *testing.T, ts *httptest.Server, method, path, token, body string) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	httpReq, err := http.NewRequest(method, ts.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}
	if method != http.MethodGet {
		httpReq.Header.Set("Idempotency-Key", "asm-"+method+path)
		httpReq.Header.Set("Content-Type", "application/json")
	}
	resp, err := ts.Client().Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// TestAssembledControlPlaneServesAndIssues is the S7.7 headline acceptance: the
// real composition root (store + event log + projections + orchestrator + API +
// signer-backed CA) answers real API requests end-to-end, serves health, and
// issues a certificate whose signing key lives in the out-of-process signer.
func TestAssembledControlPlaneServesAndIssues(t *testing.T) {
	if testing.Short() {
		t.Skip("assembles the control plane with a real signer child; skipped in -short")
	}
	st := newStore(t)
	log := openLog(t)
	prov, stop := startSignerChild(t)
	defer stop()

	asm, err := server.Build(context.Background(), server.Deps{Store: st, Log: log, Signer: prov})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ts := httptest.NewServer(asm.Handler())
	defer ts.Close()

	// Health endpoint reports ready (API up, signer reachable).
	if code, _ := req(t, ts, http.MethodGet, "/healthz", "", ""); code != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", code)
	}

	// A real API request end-to-end through the assembled process: create an
	// owner, then read it back.
	token := mintToken(t, st, "owners:write", "owners:read")
	if code, body := req(t, ts, http.MethodPost, "/api/v1/owners", token, `{"kind":"workload","name":"payments"}`); code != http.StatusCreated {
		t.Fatalf("create owner = %d: %s", code, body)
	}
	code, body := req(t, ts, http.MethodGet, "/api/v1/owners", token, "")
	if code != http.StatusOK || !strings.Contains(string(body), "payments") {
		t.Fatalf("list owners = %d: %s", code, body)
	}

	// Issue a certificate. The CA key is held by the signer; signing crosses the
	// process boundary, and the leaf verifies against the assembled CA.
	if !asm.OutOfProcessSigning() {
		t.Fatal("assembled CA signing is not out of process (AN-4)")
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer leafKey.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "payments.svc", DNSNames: []string{"payments.svc"},
	}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM, err := asm.IssueLeaf(context.Background(), csrDER, time.Hour)
	if err != nil {
		t.Fatalf("IssueLeaf through the assembled signer: %v", err)
	}
	// Read it back: the leaf chains to the assembled CA, and is the subscriber.
	leafDER := decodePEM(t, leafPEM)
	caDER := decodePEM(t, asm.CACertPEM())
	if err := crypto.VerifyLeafSignedByCA(leafDER, caDER); err != nil {
		t.Errorf("issued leaf does not verify against the assembled CA: %v", err)
	}
	info, err := certinfo.Inspect(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(info.Subject, "payments.svc") {
		t.Errorf("leaf subject %q, want it to contain payments.svc", info.Subject)
	}
}

// TestAssembledIssuanceFailsClosedWithoutSigner: with no signer wired, issuance
// returns an error rather than ever signing in-process (AN-4 fail-closed).
func TestAssembledIssuanceFailsClosedWithoutSigner(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	asm, err := server.Build(context.Background(), server.Deps{Store: st, Log: log, Signer: nil})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if asm.OutOfProcessSigning() {
		t.Fatal("no signer was wired, yet OutOfProcessSigning reports a signer")
	}
	if _, err := asm.IssueLeaf(context.Background(), []byte("ignored"), time.Hour); err == nil {
		t.Fatal("IssueLeaf without a signer must fail closed, never sign in-process")
	}
}

// TestAssembledFailsClosedWhenSignerStops: once the signer child is gone,
// issuance fails closed rather than degrading to in-process signing.
func TestAssembledFailsClosedWhenSignerStops(t *testing.T) {
	if testing.Short() {
		t.Skip("uses a real signer child; skipped in -short")
	}
	st := newStore(t)
	log := openLog(t)
	prov, stop := startSignerChild(t)

	asm, err := server.Build(context.Background(), server.Deps{Store: st, Log: log, Signer: prov})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	leafKey, _ := crypto.GenerateLockedKey(crypto.ECDSAP256)
	defer leafKey.Destroy()
	csrDER, _ := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "svc"}, leafKey)

	// Issuance works while the signer is up.
	if _, err := asm.IssueLeaf(context.Background(), csrDER, time.Hour); err != nil {
		t.Fatalf("issuance while signer up: %v", err)
	}
	// Now the signer goes away.
	stop()
	if _, err := asm.IssueLeaf(context.Background(), csrDER, time.Hour); err == nil {
		t.Fatal("issuance after the signer stopped must fail closed")
	}
}

// TestAssembledShutdownDrainsOutbox: shutdown delivers pending outbox entries —
// no enqueued external effect is lost (AN-6).
func TestAssembledShutdownDrainsOutbox(t *testing.T) {
	st := newStore(t)
	log := openLog(t)
	var delivered int64
	asm, err := server.Build(context.Background(), server.Deps{
		Store: st, Log: log,
		OutboxHandler: orchestrator.HandlerFunc(func(context.Context, orchestrator.Message) error {
			atomic.AddInt64(&delivered, 1)
			return nil
		}),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Enqueue two entries in committed transactions (as a state change would).
	ob := orchestrator.NewOutbox(st)
	for i := 0; i < 2; i++ {
		key := "drain-" + string(rune('a'+i))
		if err := st.WithTenant(context.Background(), tenantA, func(tx pgx.Tx) error {
			_, e := ob.Enqueue(context.Background(), tx, orchestrator.Entry{
				TenantID: tenantA, Destination: "webhook", IdempotencyKey: key, Payload: []byte(`{}`),
			})
			return e
		}); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}

	if err := asm.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if got := atomic.LoadInt64(&delivered); got != 2 {
		t.Errorf("drain delivered %d entries, want 2 (no lost events)", got)
	}
	if rem, err := ob.Pending(context.Background(), tenantA); err != nil || len(rem) != 0 {
		t.Errorf("after drain: %d pending (err %v), want 0", len(rem), err)
	}
}

func decodePEM(t *testing.T, p []byte) []byte {
	t.Helper()
	blk, _ := pem.Decode(p)
	if blk == nil {
		t.Fatalf("not PEM: %s", p)
	}
	return blk.Bytes
}
