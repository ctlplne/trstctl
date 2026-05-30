package drift_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"certctl.io/certctl/internal/agent/drift"
)

// recorder is an in-memory Auditor capturing the drift events emitted.
type recorder struct{ events []drift.Event }

func (r *recorder) Record(e drift.Event) { r.events = append(r.events, e) }

// install writes a declared file and returns the Watched record describing it.
func install(t *testing.T, path, class string, content []byte) drift.Watched {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return drift.Watched{Path: path, Class: class, Fingerprint: drift.Fingerprint(content), Mode: 0o644}
}

func certBytes() []byte {
	return []byte("-----BEGIN CERTIFICATE-----\ndeclared\n-----END CERTIFICATE-----\n")
}

// A file that matches its declared content and mode is not drift.
func TestDetectNoDrift(t *testing.T) {
	dir := t.TempDir()
	w := install(t, filepath.Join(dir, "app.crt"), "certificate", certBytes())

	findings, err := drift.Detect([]drift.Watched{w})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no drift, got %+v", findings)
	}
}

// A removed declared file is detected as deletion.
func TestDetectDeleted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.crt")
	w := install(t, path, "certificate", certBytes())
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	findings, err := drift.Detect([]drift.Watched{w})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Type != drift.Deleted {
		t.Fatalf("expected Deleted, got %+v", findings)
	}
}

// A file whose content changed is detected as replacement.
func TestDetectReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.crt")
	w := install(t, path, "certificate", certBytes())
	if err := os.WriteFile(path, []byte("-----BEGIN CERTIFICATE-----\nIMPOSTER\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, _ := drift.Detect([]drift.Watched{w})
	if len(findings) != 1 || findings[0].Type != drift.Replaced {
		t.Fatalf("expected Replaced, got %+v", findings)
	}
}

// A declared file moved to a sibling path is detected as relocation (not just
// deletion), reporting where the content now lives.
func TestDetectRelocated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.crt")
	moved := filepath.Join(dir, "app.crt.bak")
	w := install(t, path, "certificate", certBytes())
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}

	findings, _ := drift.Detect([]drift.Watched{w})
	if len(findings) != 1 || findings[0].Type != drift.Relocated {
		t.Fatalf("expected Relocated, got %+v", findings)
	}
	if findings[0].FoundAt != moved {
		t.Errorf("FoundAt = %q, want %q", findings[0].FoundAt, moved)
	}
}

// AlertOnly records the drift but neither blocks nor remediates; the file is
// left as-is.
func TestReconcileAlertOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.crt")
	w := install(t, path, "certificate", certBytes())
	_ = os.WriteFile(path, []byte("changed"), 0o644)

	rec := &recorder{}
	r := &drift.Reconciler{
		Policy:   drift.ClassPolicy{"certificate": drift.AlertOnly},
		Auditor:  rec,
		Restorer: drift.NewFileRestorer(map[string][]byte{path: certBytes()}),
	}
	rep, err := r.Reconcile(context.Background(), []drift.Watched{w})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Events) != 1 || rep.Events[0].Type != drift.Replaced {
		t.Fatalf("expected one Replaced event, got %+v", rep.Events)
	}
	if len(rep.Blocked) != 0 || len(rep.Remediated) != 0 {
		t.Errorf("alert-only must not block or remediate: %+v", rep)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, []byte("changed")) {
		t.Error("alert-only must not modify the file")
	}
	if len(rec.events) != 1 {
		t.Errorf("drift must be audited exactly once, got %d", len(rec.events))
	}
}

// AlertAndBlock records the drift and blocks the credential, without modifying
// the file.
func TestReconcileAlertAndBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.key")
	w := install(t, path, "private-key", certBytes())
	_ = os.Remove(path)

	rec := &recorder{}
	r := &drift.Reconciler{
		Policy:  drift.ClassPolicy{"private-key": drift.AlertAndBlock},
		Auditor: rec,
	}
	rep, err := r.Reconcile(context.Background(), []drift.Watched{w})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Blocked) != 1 || rep.Blocked[0] != path {
		t.Fatalf("expected %q blocked, got %+v", path, rep.Blocked)
	}
	if len(rep.Remediated) != 0 {
		t.Error("block must not remediate")
	}
	if len(rec.events) != 1 || !rec.events[0].Blocked {
		t.Errorf("blocked drift must be audited with Blocked set: %+v", rec.events)
	}
}

// AutoRemediate restores a replaced file to its declared content and audits the
// remediation.
func TestReconcileAutoRemediateReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.crt")
	w := install(t, path, "certificate", certBytes())
	_ = os.WriteFile(path, []byte("IMPOSTER"), 0o644)

	rec := &recorder{}
	r := &drift.Reconciler{
		Policy:   drift.ClassPolicy{"certificate": drift.AutoRemediate},
		Auditor:  rec,
		Restorer: drift.NewFileRestorer(map[string][]byte{path: certBytes()}),
	}
	rep, err := r.Reconcile(context.Background(), []drift.Watched{w})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Remediated) != 1 {
		t.Fatalf("expected remediation, got %+v", rep)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, certBytes()) {
		t.Error("auto-remediate must restore the declared content")
	}
	if len(rec.events) != 1 || !rec.events[0].Remediated {
		t.Errorf("remediation must be audited with Remediated set: %+v", rec.events)
	}
}

// AutoRemediate of a relocation restores the declared path and removes the stray
// copy.
func TestReconcileAutoRemediateRelocated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.crt")
	moved := filepath.Join(dir, "app.crt.bak")
	w := install(t, path, "certificate", certBytes())
	_ = os.Rename(path, moved)

	r := &drift.Reconciler{
		Policy:   drift.ClassPolicy{"certificate": drift.AutoRemediate},
		Auditor:  &recorder{},
		Restorer: drift.NewFileRestorer(map[string][]byte{path: certBytes()}),
	}
	if _, err := r.Reconcile(context.Background(), []drift.Watched{w}); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, certBytes()) {
		t.Errorf("declared path not restored: %v", err)
	}
	if _, err := os.Stat(moved); !os.IsNotExist(err) {
		t.Error("the relocated stray copy must be removed")
	}
}

// An unknown class defaults to alert-only (the safest mode), and every drift is
// audited even across multiple files.
func TestReconcileAuditsEveryDriftAndDefaultsSafe(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.crt")
	b := filepath.Join(dir, "b.crt")
	wa := install(t, a, "certificate", certBytes())
	wb := install(t, b, "unknown-class", certBytes())
	_ = os.Remove(a)
	_ = os.WriteFile(b, []byte("changed"), 0o644)

	rec := &recorder{}
	r := &drift.Reconciler{
		Policy:  drift.ClassPolicy{"certificate": drift.AutoRemediate},
		Auditor: rec,
		Restorer: drift.NewFileRestorer(map[string][]byte{
			a: certBytes(), b: certBytes(),
		}),
	}
	rep, err := r.Reconcile(context.Background(), []drift.Watched{wa, wb})
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.events) != 2 {
		t.Fatalf("expected 2 audited drifts, got %d", len(rec.events))
	}
	// b's unknown class defaulted to alert-only: not remediated.
	if got, _ := os.ReadFile(b); !bytes.Equal(got, []byte("changed")) {
		t.Error("unknown class must default to alert-only (no remediation)")
	}
	if len(rep.Remediated) != 1 {
		t.Errorf("only the certificate-class deletion should be remediated, got %+v", rep.Remediated)
	}
}

// The platform's permission-detection capability is reported on every pass so the
// agent can surface a gap to operators. The CI platforms (Linux, Windows) both
// support it.
func TestPermissionDetectionCapabilityReported(t *testing.T) {
	if !drift.SupportsPermissionDetection() {
		t.Error("permission detection should be supported on this platform (POSIX or Windows)")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "app.crt")
	w := install(t, path, "certificate", certBytes())
	_ = os.Remove(path) // produce one finding so Reconcile runs a pass

	r := &drift.Reconciler{Policy: drift.ClassPolicy{}, Auditor: &recorder{}}
	rep, err := r.Reconcile(context.Background(), []drift.Watched{w})
	if err != nil {
		t.Fatal(err)
	}
	if rep.PermissionDetectionSupported != drift.SupportsPermissionDetection() {
		t.Error("Report.PermissionDetectionSupported must match SupportsPermissionDetection()")
	}
}
