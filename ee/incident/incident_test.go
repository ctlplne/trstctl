package incident

import (
	"context"
	"errors"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/idem"
)

type fakeRem struct {
	mu                      sync.Mutex
	reissued, revoked       []string
	rotated                 []string
	failRevoke, failReissue map[string]bool
}

func (r *fakeRem) Reissue(_ context.Context, _, cred string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failReissue[cred] {
		return "", errors.New("reissue boom")
	}
	r.reissued = append(r.reissued, cred)
	return cred + "-new", nil
}
func (r *fakeRem) Revoke(_ context.Context, _, cred string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failRevoke[cred] {
		return errors.New("revoke boom")
	}
	r.revoked = append(r.revoked, cred)
	return nil
}
func (r *fakeRem) Rotate(_ context.Context, _, cred string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rotated = append(r.rotated, cred)
	return nil
}

// seed builds: credA -> credB -> credC (multi-hop downstream credentials) and
// credA -> res1 (a resource), so a compromise of credA reaches credC at depth 2.
func seed() *graph.Graph {
	g := graph.New()
	for _, id := range []string{"credA", "credB", "credC"} {
		g.AddNode(graph.Node{ID: id, Kind: graph.KindCredential, Name: id})
	}
	g.AddNode(graph.Node{ID: "res1", Kind: graph.KindResource, Name: "res1"})
	g.AddEdge(graph.Edge{From: "credA", To: "credB", Type: graph.EdgeConnectsTo})
	g.AddEdge(graph.Edge{From: "credB", To: "credC", Type: graph.EdgeConnectsTo})
	g.AddEdge(graph.Edge{From: "credA", To: "res1", Type: graph.EdgeGrantsAccess})
	return g
}

func newWF(t *testing.T, g *graph.Graph, rem Remediator, rec auditsink.Auditor) *Workflow {
	t.Helper()
	w, err := New(Config{TenantID: "t1", Graph: g, Remediator: rem, Idem: idem.NewMemory(), Audit: rec})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestPreviewBlastRadiusMultiHop(t *testing.T) {
	w := newWF(t, seed(), &fakeRem{}, nil)
	p := w.Preview("credA")
	if p.CredentialCount != 2 {
		t.Errorf("credential count = %d, want 2 (credB, credC)", p.CredentialCount)
	}
	sawC := false
	for _, n := range p.Affected {
		if n.ID == "credC" {
			sawC = true
		}
	}
	if !sawC {
		t.Error("blast radius missing the multi-hop downstream credential credC")
	}
}

func TestRemediateFullChain(t *testing.T) {
	rem := &fakeRem{}
	rec := &auditsink.Recorder{}
	w := newWF(t, seed(), rem, rec)
	rep, err := w.Remediate(context.Background(), "credA", "k1")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Completed {
		t.Fatalf("remediation not complete: %+v", rep.Steps)
	}
	if len(rem.reissued) != 3 || len(rem.revoked) != 3 || len(rem.rotated) != 3 {
		t.Errorf("expected all 3 credentials remediated: reissued=%v revoked=%v rotated=%v", rem.reissued, rem.revoked, rem.rotated)
	}
	if rec.Count("incident.completed") != 1 {
		t.Error("completion not audited")
	}
}

func TestRemediatePartialFailureIsRecoverable(t *testing.T) {
	rem := &fakeRem{failRevoke: map[string]bool{"credB": true}}
	rec := &auditsink.Recorder{}
	w := newWF(t, seed(), rem, rec)
	rep, err := w.Remediate(context.Background(), "credA", "k1")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Completed {
		t.Error("report marked complete despite an injected failure")
	}
	if !rep.Recoverable {
		t.Error("partial failure left a non-recoverable (outage) state")
	}
	// Every step — including the failed one — must still leave a valid credential.
	for _, s := range rep.Steps {
		if !s.HasValidCredential {
			t.Errorf("credential %s left without a valid credential (half-remediated outage)", s.CredentialID)
		}
		if s.CredentialID == "credB" {
			if s.Reissued == "" {
				t.Error("credB was not reissued before the revoke failure")
			}
			if s.RevokeOK {
				t.Error("credB revoke reported OK but was injected to fail")
			}
		}
	}
}

func TestRemediateIdempotent(t *testing.T) {
	rem := &fakeRem{}
	w := newWF(t, seed(), rem, &auditsink.Recorder{})
	if _, err := w.Remediate(context.Background(), "credA", "same"); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Remediate(context.Background(), "credA", "same"); err != nil {
		t.Fatal(err)
	}
	if len(rem.reissued) != 3 {
		t.Errorf("idempotent replay re-ran remediation: reissued %d times, want 3", len(rem.reissued))
	}
}
