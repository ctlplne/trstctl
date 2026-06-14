package fleet

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/graph"
)

type fakeReissuer struct {
	mu  sync.Mutex
	ids []string
}

func (r *fakeReissuer) Reissue(_ context.Context, _, id string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ids = append(r.ids, id)
	return id + "-new", nil
}

type fakeRollback struct{ rolled []string }

func (r *fakeRollback) Rollback(_ context.Context, _ string, ids []string) error {
	r.rolled = append(r.rolled, ids...)
	return nil
}

type guardFn func(ctx context.Context, tenantID, credID string) (bool, string)

func (g guardFn) Allow(ctx context.Context, t, c string) (bool, string) { return g(ctx, t, c) }

type fakeSSH struct{ rotated, redistributed, krlPublished, krlRevoked int }

func (s *fakeSSH) RotateCAKey(_ context.Context, _, ca string) (string, error) {
	s.rotated++
	return ca + "-key2", nil
}
func (s *fakeSSH) RedistributeTrust(_ context.Context, _, _, _ string) error {
	s.redistributed++
	return nil
}
func (s *fakeSSH) PublishKRL(_ context.Context, _, _ string, revoked []string) error {
	s.krlPublished++
	s.krlRevoked = len(revoked)
	return nil
}

func fleetGraph(n int) *graph.Graph {
	g := graph.New()
	g.AddNode(graph.Node{ID: "ca1", Kind: graph.KindIssuer, Name: "ca1"})
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("leaf%d", i)
		g.AddNode(graph.Node{ID: id, Kind: graph.KindCredential, Name: id})
		g.AddEdge(graph.Edge{From: "ca1", To: id, Type: graph.EdgeIssued})
	}
	return g
}

func TestFleetStagedHappyPath(t *testing.T) {
	rec := &auditsink.Recorder{}
	f, _ := New(Config{TenantID: "t1", Graph: fleetGraph(5), Reissuer: &fakeReissuer{}, StageSize: 2, Progress: NewMemoryProgress(), Audit: rec})
	rep, err := f.ReissueFleet(context.Background(), "ca1", "run1")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Completed || rep.Reissued != 5 || rep.Stages != 3 {
		t.Fatalf("report = %+v, want completed/5/3", rep)
	}
	if rec.Count("fleet.completed") != 1 {
		t.Error("completion not audited")
	}
}

func TestFleetHealthCheckRollback(t *testing.T) {
	rr := &fakeReissuer{}
	rb := &fakeRollback{}
	health := func(_ context.Context, stage int) error {
		if stage == 2 {
			return errors.New("fleet unhealthy")
		}
		return nil
	}
	f, _ := New(Config{TenantID: "t1", Graph: fleetGraph(5), Reissuer: rr, Health: health, Rollback: rb, StageSize: 2, Progress: NewMemoryProgress()})
	rep, err := f.ReissueFleet(context.Background(), "ca1", "run2")
	if err == nil {
		t.Fatal("expected an error after a failed health check")
	}
	if !rep.RolledBack || rep.FailedStage != 2 {
		t.Errorf("report = %+v, want RolledBack/FailedStage=2", rep)
	}
	if len(rb.rolled) != 2 {
		t.Errorf("rolled back %d credentials, want 2 (the failed stage)", len(rb.rolled))
	}
}

func TestFleetResumesWithoutDuplicateIssuance(t *testing.T) {
	prog := NewMemoryProgress()
	ctx := context.Background()
	_ = prog.Mark(ctx, "run3", "leaf0", "leaf0-new")
	_ = prog.Mark(ctx, "run3", "leaf1", "leaf1-new")
	rr := &fakeReissuer{}
	f, _ := New(Config{TenantID: "t1", Graph: fleetGraph(5), Reissuer: rr, StageSize: 2, Progress: prog})
	rep, err := f.ReissueFleet(ctx, "ca1", "run3")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Skipped != 2 || rep.Reissued != 3 {
		t.Errorf("report = %+v, want Skipped=2 Reissued=3 (resume)", rep)
	}
	if len(rr.ids) != 3 {
		t.Errorf("reissuer called %d times, want 3 (no duplicate issuance on resume)", len(rr.ids))
	}
}

func TestFleetSSHReestablishesTrust(t *testing.T) {
	ssh := &fakeSSH{}
	f, _ := New(Config{TenantID: "t1", Graph: fleetGraph(5), Reissuer: &fakeReissuer{}, SSH: ssh, StageSize: 10, Progress: NewMemoryProgress()})
	rep, err := f.ReissueFleet(context.Background(), "ca1", "run4")
	if err != nil {
		t.Fatal(err)
	}
	if rep.NewCAKeyID != "ca1-key2" {
		t.Errorf("new CA key = %q", rep.NewCAKeyID)
	}
	if ssh.rotated != 1 || ssh.redistributed != 1 || ssh.krlPublished != 1 {
		t.Errorf("ssh seam calls: rotate=%d redistribute=%d krl=%d, want 1/1/1", ssh.rotated, ssh.redistributed, ssh.krlPublished)
	}
	if ssh.krlRevoked != 5 {
		t.Errorf("KRL revoked %d, want 5", ssh.krlRevoked)
	}
}

func TestFleetPolicyGuardSkips(t *testing.T) {
	rr := &fakeReissuer{}
	guard := guardFn(func(_ context.Context, _, id string) (bool, string) {
		if id == "leaf2" {
			return false, "policy: not eligible"
		}
		return true, ""
	})
	f, _ := New(Config{TenantID: "t1", Graph: fleetGraph(5), Reissuer: rr, Guard: guard, StageSize: 10, Progress: NewMemoryProgress()})
	rep, err := f.ReissueFleet(context.Background(), "ca1", "run5")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Reissued != 4 || rep.Skipped != 1 {
		t.Errorf("report = %+v, want Reissued=4 Skipped=1 (guard)", rep)
	}
}
