package pqcmigration

import (
	"context"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/fleet"
	"trstctl.com/trstctl/internal/graph"
)

type fakeReissuer struct {
	mu  sync.Mutex
	ids []string
}

func (r *fakeReissuer) ReissueToPQC(_ context.Context, _, id string, _ crypto.Algorithm) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ids = append(r.ids, id)
	return id + "-pqc", nil
}

func cbom() *graph.Graph {
	g := graph.New()
	add := func(id string, alg crypto.Algorithm) {
		g.AddNode(graph.Node{ID: id, Kind: graph.KindCryptoAsset, Name: id, Attrs: map[string]string{"algorithm": string(alg)}})
	}
	add("a-rsa", crypto.RSA2048)
	add("a-ecdsa", crypto.ECDSAP256)
	add("a-rsa4k", crypto.RSA4096)
	add("a-pqc", crypto.MLDSA65) // already post-quantum
	return g
}

func TestVulnerableAssetsFromCBOM(t *testing.T) {
	o, _ := New(Config{TenantID: "t1", Graph: cbom(), Reissuer: &fakeReissuer{}, Progress: fleet.NewMemoryProgress()})
	v := o.VulnerableAssets()
	if len(v) != 3 {
		t.Fatalf("vulnerable = %d, want 3 (RSA, ECDSA, RSA — not the ML-DSA one)", len(v))
	}
}

func TestMigrateToPQCCompletes(t *testing.T) {
	rr := &fakeReissuer{}
	rec := &auditsink.Recorder{}
	g := cbom()
	o, _ := New(Config{TenantID: "t1", Graph: g, Reissuer: rr, Progress: fleet.NewMemoryProgress(), Audit: rec})
	rep, err := o.Migrate(context.Background(), "run1", crypto.SLHDSA128f)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Migrated != 3 || rep.Remaining != 0 || !rep.Completed {
		t.Fatalf("report = %+v, want Migrated=3 Remaining=0 Completed", rep)
	}
	if len(rr.ids) != 3 {
		t.Errorf("reissuer called %d times, want 3", len(rr.ids))
	}
	if rec.Count("pqc.migration.completed") != 1 {
		t.Error("completion not audited")
	}
}

func TestMigrateRejectsNonPQCTarget(t *testing.T) {
	o, _ := New(Config{TenantID: "t1", Graph: cbom(), Reissuer: &fakeReissuer{}, Progress: fleet.NewMemoryProgress()})
	if _, err := o.Migrate(context.Background(), "run1", crypto.RSA2048); err == nil {
		t.Error("migration accepted a non-post-quantum target")
	}
}

func TestMigrateResumesAndPolicyGates(t *testing.T) {
	// Resume: one asset already migrated is skipped.
	prog := fleet.NewMemoryProgress()
	_ = prog.Mark(context.Background(), "run1", "a-rsa", "a-rsa-pqc")
	rr := &fakeReissuer{}
	g := cbom()
	o, _ := New(Config{TenantID: "t1", Graph: g, Reissuer: rr, Progress: prog,
		Guard: func(id string) bool { return id != "a-ecdsa" }, // policy denies a-ecdsa
	})
	rep, err := o.Migrate(context.Background(), "run1", crypto.SLHDSA128f)
	if err != nil {
		t.Fatal(err)
	}
	// a-rsa skipped (resume), a-ecdsa skipped (policy), a-rsa4k migrated.
	if rep.Migrated != 1 || rep.Skipped != 2 {
		t.Errorf("report = %+v, want Migrated=1 Skipped=2", rep)
	}
	// a-ecdsa remains vulnerable -> not complete.
	if rep.Completed || rep.Remaining != 1 {
		t.Errorf("report = %+v, want Remaining=1 not-complete", rep)
	}
}
