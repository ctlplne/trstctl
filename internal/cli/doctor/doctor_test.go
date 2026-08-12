// SPDX-License-Identifier: MPL-2.0

package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	boundarycrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/signing"
	"trstctl.com/trstctl/internal/store"
)

var testDSN string

// TestMain starts one real embedded PostgreSQL so every doctor probe runs
// against the same migrated, FORCE-d RLS schema the product ships — the
// anti-vacuity tests then break real invariants and watch probes go red.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trstctl-doctor-pg")
	if err != nil {
		panic(err)
	}
	port := freePort()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Port(uint32(port)). // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
		RuntimePath(dir + "/rt").
		DataPath(dir + "/data").
		BinariesPath(dir + "/bin"). // per-package, so parallel packages don't race the extraction
		Logger(io.Discard).
		StartTimeout(60 * time.Second))
	if err := pg.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "embedded postgres start:", err)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	testDSN = fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres", port)

	ctx := context.Background()
	s, err := store.Open(ctx, testDSN)
	if err == nil {
		err = s.Migrate(ctx)
		s.Close()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		_ = pg.Stop()
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}

	code := m.Run()
	_ = pg.Stop()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func getenvNone(string) string { return "" }

func runDoctor(t *testing.T, args ...string) (Receipt, string, int) {
	t.Helper()
	receiptPath := filepath.Join(t.TempDir(), "receipt.json")
	var stdout, stderr bytes.Buffer
	full := append([]string{"--postgres-dsn", testDSN, "--json", receiptPath}, args...)
	err := Run(context.Background(), full, getenvNone, &stdout, &stderr)
	code := 0
	if err != nil {
		exit, ok := err.(ExitError)
		if !ok {
			t.Fatalf("doctor returned a non-exit error: %v (stderr %s)", err, stderr.String())
		}
		code = exit.Code
	}
	blob, rerr := os.ReadFile(receiptPath) // #nosec G304 -- test reads its own tempdir receipt (CWE-22)
	if rerr != nil {
		t.Fatalf("receipt not written: %v (stderr %s)", rerr, stderr.String())
	}
	var r Receipt
	if err := json.Unmarshal(blob, &r); err != nil {
		t.Fatalf("receipt does not parse: %v", err)
	}
	return r, stdout.String(), code
}

func probeByID(t *testing.T, r Receipt, id string) Probe {
	t.Helper()
	for _, p := range r.Probes {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("receipt has no probe %q", id)
	return Probe{}
}

func systemExec(t *testing.T, sql string) {
	t.Helper()
	s, err := store.Open(context.Background(), testDSN)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if _, err := s.SystemPool().Exec(context.Background(), sql); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

// TestDoctorHealthyDeploymentPasses is the green direction: on the migrated
// schema every isolation probe passes with --write-probe, the write probes
// leave zero residue, the receipt validates, and the exit code is 0.
func TestDoctorHealthyDeploymentPasses(t *testing.T) {
	r, out, code := runDoctor(t, "--prove-isolation", "--write-probe")
	if code != 0 {
		t.Fatalf("healthy deployment exit = %d, want 0\n%s", code, out)
	}
	if r.Schema != "trstctl.doctor.v1" {
		t.Fatalf("receipt schema = %q", r.Schema)
	}
	if r.Summary.Fail != 0 {
		t.Fatalf("healthy deployment reports %d failures: %+v", r.Summary.Fail, r.Probes)
	}
	for _, id := range []string{"ISO-1", "ISO-2", "ISO-3", "ISO-4", "ISO-5", "ISO-6", "ISO-LEAK", "ISO-CLEAN", "POSTURE-1"} {
		if p := probeByID(t, r, id); p.Status != StatusPass {
			t.Errorf("%s = %s (%s), want pass", id, p.Status, p.Detail)
		}
	}
	// The honest skips stay skips, with reasons.
	for _, id := range []string{"SIG-1", "SIG-3", "EVT-1", "DUR-1", "ISO-7"} {
		p := probeByID(t, r, id)
		if p.Status != StatusSkip || p.Detail == "" {
			t.Errorf("%s = %s (%q), want an explained skip", id, p.Status, p.Detail)
		}
	}
	if tc := probeByID(t, r, "ISO-1").Evidence["tables_checked"]; tc == nil {
		t.Error("ISO-1 carries no tables_checked evidence")
	}
	if r.Summary.Pass+r.Summary.Fail+r.Summary.Warn+r.Summary.Skip != len(r.Probes) {
		t.Errorf("summary does not tile the probe list: %+v over %d probes", r.Summary, len(r.Probes))
	}
}

// TestDoctorWithoutWriteProbeSkipsAndNeverWrites: the write probes report
// SKIPPED (never pass), and the run leaves no rows under the probe prefix —
// read-only mode never mutates.
func TestDoctorWithoutWriteProbeSkipsAndNeverWrites(t *testing.T) {
	r, _, code := runDoctor(t, "--prove-isolation")
	if code != 0 {
		t.Fatalf("read-only doctor exit = %d, want 0", code)
	}
	for _, id := range []string{"ISO-3", "ISO-4", "ISO-5"} {
		p := probeByID(t, r, id)
		if p.Status != StatusSkip {
			t.Errorf("%s without --write-probe = %s, want skip (a skipped proof must never look passed)", id, p.Status)
		}
		if !strings.Contains(p.Detail, "--write-probe") {
			t.Errorf("%s skip detail %q does not tell the operator how to run the full proof", id, p.Detail)
		}
	}
	s, err := store.Open(context.Background(), testDSN)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if n, err := s.DoctorProbeResidue(context.Background(), ProbeTenantPrefix); err != nil || n != 0 {
		t.Fatalf("read-only doctor left %d probe rows (err %v), want 0 writes", n, err)
	}
}

// TestDoctorFailsWhenForceRLSDropped is the ISO-1 anti-vacuity proof: drop
// FORCE from one tenant table and doctor must go red with exit 1, naming the
// table; restore FORCE and it must go green again.
func TestDoctorFailsWhenForceRLSDropped(t *testing.T) {
	systemExec(t, `ALTER TABLE agents NO FORCE ROW LEVEL SECURITY`)
	restored := false
	restore := func() {
		if !restored {
			systemExec(t, `ALTER TABLE agents FORCE ROW LEVEL SECURITY`)
			restored = true
		}
	}
	defer restore()

	r, _, code := runDoctor(t, "--prove-isolation")
	if code != 1 {
		t.Fatalf("doctor with FORCE dropped exit = %d, want 1", code)
	}
	p := probeByID(t, r, "ISO-1")
	if p.Status != StatusFail || !strings.Contains(p.Detail, "agents") {
		t.Fatalf("ISO-1 with FORCE dropped = %s (%q), want fail naming agents", p.Status, p.Detail)
	}

	restore()
	if r, _, code := runDoctor(t, "--prove-isolation"); code != 0 || probeByID(t, r, "ISO-1").Status != StatusPass {
		t.Fatalf("ISO-1 did not recover after restoring FORCE (exit %d)", code)
	}
}

// TestDoctorFailsWhenIsolationPolicyDropped is the ISO-3 anti-vacuity proof:
// drop the agents isolation policy and the cross-tenant read probe must
// observe the leak and fail; the probes must still clean up after themselves
// even mid-failure, and restoring the policy turns doctor green again.
func TestDoctorFailsWhenIsolationPolicyDropped(t *testing.T) {
	systemExec(t, `DROP POLICY agents_isolation ON agents`)
	restored := false
	restore := func() {
		if !restored {
			systemExec(t, `CREATE POLICY agents_isolation ON agents
				USING (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)
				WITH CHECK (tenant_id = current_setting('trstctl.tenant_id', true)::uuid)`)
			restored = true
		}
	}
	defer restore()

	r, _, code := runDoctor(t, "--prove-isolation", "--write-probe")
	if code != 1 {
		t.Fatalf("doctor with the isolation policy dropped exit = %d, want 1", code)
	}
	// With no policy, FORCE-d RLS denies the app role everything: the probe
	// fails at seeding or at the cross-tenant step — either way ISO-3 is red.
	if p := probeByID(t, r, "ISO-3"); p.Status != StatusFail {
		t.Fatalf("ISO-3 with the policy dropped = %s (%q), want fail", p.Status, p.Detail)
	}
	// Cleanup still ran and verified zero residue after the induced failure.
	if p := probeByID(t, r, "ISO-CLEAN"); p.Status != StatusPass {
		t.Fatalf("ISO-CLEAN after induced failure = %s (%q); probes must clean up even when failing", p.Status, p.Detail)
	}

	restore()
	if r, _, code := runDoctor(t, "--prove-isolation", "--write-probe"); code != 0 || probeByID(t, r, "ISO-3").Status != StatusPass {
		t.Fatalf("ISO-3 did not recover after restoring the policy (exit %d)", code)
	}
}

// TestDoctorFailsOnLeakedProbeTenant: rows left under the reserved synthetic
// prefix by a prior run are a FAIL on the next run, even read-only.
func TestDoctorFailsOnLeakedProbeTenant(t *testing.T) {
	leaked := ProbeTenantPrefix + "-4000-8000-00000000dead"
	systemExec(t, fmt.Sprintf(`INSERT INTO agents (id, tenant_id, name, status, created_at)
		VALUES ('11111111-2222-4333-8444-555555555555', '%s', 'leaked-probe', 'active', now())`, leaked))
	defer systemExec(t, fmt.Sprintf(`DELETE FROM agents WHERE tenant_id = '%s'`, leaked))

	r, _, code := runDoctor(t, "--prove-isolation")
	if code != 1 {
		t.Fatalf("doctor with a leaked probe tenant exit = %d, want 1", code)
	}
	if p := probeByID(t, r, "ISO-LEAK"); p.Status != StatusFail || !strings.Contains(p.Detail, ProbeTenantPrefix) {
		t.Fatalf("ISO-LEAK = %s (%q), want fail naming the reserved prefix", p.Status, p.Detail)
	}
}

// TestDoctorSignsReceiptWithAuditKey: --sign binds the deployment's existing,
// purpose-constrained audit-export handle through the signer socket. Doctor
// never reads or parses a private key (AUD-63 / AN-4).
func TestDoctorSignsReceiptWithAuditKey(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	socketDir, err := os.MkdirTemp("", "doctor-signer")
	if err != nil {
		t.Fatalf("MkdirTemp signer: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "s.sock")
	signerServer := signing.NewServer()
	served := make(chan error, 1)
	go func() {
		served <- signing.ServeServerWithOptions(ctx, socket, signerServer, signing.ServeOptions{
			AllowInsecureDevNonLinux: runtime.GOOS != "linux",
		})
	}()
	client, err := signing.DialReady(ctx, socket, 10*time.Second)
	if err != nil {
		t.Fatalf("DialReady: %v", err)
	}
	remote, err := client.GenerateConstrainedKeyHandle(
		ctx,
		boundarycrypto.RSA2048,
		"audit-export",
		[]signing.KeyPurpose{signing.PurposeAuditEvidence},
		signing.PurposeAuditEvidence,
	)
	if err != nil {
		t.Fatalf("GenerateConstrainedKeyHandle: %v", err)
	}
	key, err := jose.NewDigestSigningKey("audit-export", remote)
	if err != nil {
		t.Fatalf("NewDigestSigningKey: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close setup client: %v", err)
	}

	r, _, code := runDoctor(t, "--prove-isolation", "--sign", "--signer-socket", socket)
	if code != 0 {
		t.Fatalf("signed doctor exit = %d, want 0", code)
	}
	if r.Signature == nil || r.Signature.Alg != "RS256" || r.Signature.KeyID != "audit-export" {
		t.Fatalf("receipt signature = %+v", r.Signature)
	}
	sigParts := strings.Split(r.Signature.JWS, ".")
	if len(sigParts) != 3 {
		t.Fatalf("signature is not a compact JWS: %q", r.Signature.JWS)
	}
	// The signed body is the receipt with the signature absent; re-derive and
	// verify the JWS binds exactly that payload.
	unsigned := r
	unsigned.Signature = nil
	want, err := json.Marshal(&unsigned)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := key.JWKS().VerifyArtifact(r.Signature.JWS, jose.ArtifactDoctorReceipt)
	if err != nil {
		t.Fatalf("receipt signature does not verify against the audit key: %v", err)
	}
	if !bytes.Equal(payload, want) {
		t.Fatalf("signed payload differs from the canonical receipt body")
	}

	// Fail closed: an unavailable signer is an error; no local-key fallback exists.
	var stdout, stderr bytes.Buffer
	err = Run(context.Background(), []string{"--postgres-dsn", testDSN, "--sign", "--signer-socket", filepath.Join(t.TempDir(), "absent.sock")}, getenvNone, &stdout, &stderr)
	exit, ok := err.(ExitError)
	if !ok || exit.Code != 2 {
		t.Fatalf("doctor with an unavailable signer = %v, want ExitError{2}", err)
	}
	cancel()
	if err := <-served; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("serve signer: %v", err)
	}
}
