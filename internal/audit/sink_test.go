package audit_test

import (
	"context"
	"testing"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/events"
)

// TestNewAuditorAppendsToTheLog is the CODE-001 acceptance for the real
// production write seam: the events.Log-backed auditsink.Auditor actually appends
// to the AN-2 log (the event is then queryable via the read side, proving the
// audit trail is a projection of it), and a successful append returns nil.
func TestNewAuditorAppendsToTheLog(t *testing.T) {
	log := openLog(t)
	a := audit.NewAuditor(log)

	if err := a.Audit(context.Background(), "secret.version.written", tenantA, []byte(`{"path":"app/db","version":1}`)); err != nil {
		t.Fatalf("Audit (append) returned error: %v", err)
	}

	// The appended event is visible to the read side — i.e. it really hit the log.
	svc := newService(t, log)
	recs, err := svc.Search(context.Background(), audit.Query{TenantID: tenantA, Types: []string{"secret.version.written"}})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 appended audit record, got %d", len(recs))
	}
}

// TestNewAuditorReturnsAppendError is the CODE-001 acceptance for error
// propagation: when the underlying log cannot accept the append (here, a closed
// log), the adapter RETURNS the error rather than swallowing it — which is what
// makes handling it at the call sites meaningful. It FAILS to return an error on
// a tree where the adapter discarded it.
func TestNewAuditorReturnsAppendError(t *testing.T) {
	log, err := openClosedLog(t)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	a := audit.NewAuditor(log)
	if err := a.Audit(context.Background(), "secret.version.written", tenantA, []byte(`{}`)); err == nil {
		t.Fatal("Audit over a closed log returned nil error; want the append failure surfaced (CODE-001)")
	}
}

// openClosedLog opens an embedded event log and immediately closes it, so a
// subsequent Append fails — a deterministic stand-in for an unavailable event log.
func openClosedLog(t *testing.T) (*events.Log, error) {
	t.Helper()
	log := openLog(t)
	if err := log.Close(); err != nil {
		return nil, err
	}
	return log, nil
}
