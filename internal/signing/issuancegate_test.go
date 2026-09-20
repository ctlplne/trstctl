// SPDX-License-Identifier: BUSL-1.1

package signing

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	signerpb "trstctl.com/trstctl/internal/signing/proto"
)

// orderLog records the observed ordering of gate consults and keystore key ops so a
// test can assert that no key op is observed until the gate has been consulted and
// has approved (INV-A1).
type orderLog struct {
	mu     sync.Mutex
	events []string
}

func (l *orderLog) record(ev string) {
	l.mu.Lock()
	l.events = append(l.events, ev)
	l.mu.Unlock()
}

func (l *orderLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.events))
	copy(out, l.events)
	return out
}

func (l *orderLog) countKeyOps() int {
	n := 0
	for _, ev := range l.snapshot() {
		if ev == "keyop" {
			n++
		}
	}
	return n
}

// instrumentedKeyFactory is a KeyFactory that records every key-generation call into
// a shared order log before delegating to the default core factory. Injected via
// WithKeyFactory, it makes the signer's real key-op path observable: any keystore
// keygen the issuance path performs shows up as a "keyop" event in call order.
type instrumentedKeyFactory struct {
	inner KeyFactory
	log   *orderLog
}

func newInstrumentedKeyFactory(log *orderLog) *instrumentedKeyFactory {
	return &instrumentedKeyFactory{inner: defaultKeyFactory{}, log: log}
}

func (f *instrumentedKeyFactory) GenerateSigningKey(alg crypto.Algorithm) (Key, error) {
	f.log.record("keyop")
	return f.inner.GenerateSigningKey(alg)
}

func (f *instrumentedKeyFactory) GenerateSigningKeyFromProto(protoAlg signerpb.Algorithm) (Key, error) {
	f.log.record("keyop")
	return f.inner.GenerateSigningKeyFromProto(protoAlg)
}

func (f *instrumentedKeyFactory) SigningKeyFromSealedBytes(protoAlg signerpb.Algorithm, priv []byte) (Key, error) {
	return f.inner.SigningKeyFromSealedBytes(protoAlg, priv)
}

func (f *instrumentedKeyFactory) ProtoFromAlgorithm(alg crypto.Algorithm) signerpb.Algorithm {
	return f.inner.ProtoFromAlgorithm(alg)
}

// recordingGate is a no-op/instrumented issuance gate: it records the consult in the
// shared order log and returns the configured decision (or error). It performs NO
// key op itself, so any key op observed by the log came from the signer's key-op
// path AFTER the gate returned.
type recordingGate struct {
	log      *orderLog
	decision IssuanceDecision
	err      error
	calls    int
}

func (g *recordingGate) VerifyIssuancePreconditions(_ context.Context, _ IssuancePreconditions) (IssuanceDecision, error) {
	g.log.record("gate")
	g.calls++
	if g.err != nil {
		return IssuanceDecision{}, g.err
	}
	return g.decision, nil
}

// TestIssuanceGate_ConsultedBeforeKeyOp proves INV-A1 at the seam: with a gate
// attached and an instrumented fake keystore recording call order, zero key ops
// occur until the gate returns an Approved decision. A refusing gate yields zero key
// ops and surfaces the refusal (opaque RefusalRecord) with no key op.
func TestIssuanceGate_ConsultedBeforeKeyOp(t *testing.T) {
	ctx := context.Background()

	// The keyOp closure represents the signer's issuance key op. It drives a REAL
	// keystore key generation (GenerateSuccessorKey), which routes through the
	// instrumented key factory and records a "keyop" event. gatedIssue must call it
	// only AFTER the gate approves.
	newKeyOp := func(s *Server, handle string) func(context.Context, IssuanceDecision) error {
		return func(_ context.Context, _ IssuanceDecision) error {
			_, err := s.GenerateSuccessorKey(handle, crypto.ECDSAP256)
			return err
		}
	}

	t.Run("approved: gate consulted first, then exactly one key op", func(t *testing.T) {
		log := &orderLog{}
		gate := &recordingGate{log: log, decision: IssuanceDecision{
			Approved:        true,
			BindingMaterial: []byte("binding"),
		}}
		s := NewServer(
			WithKeyFactory(newInstrumentedKeyFactory(log)),
			WithIssuanceGate(gate),
		)

		dec, err := s.gatedIssue(ctx, IssuancePreconditions{TenantID: "t1"}, newKeyOp(s, "issued-approved"))
		if err != nil {
			t.Fatalf("gatedIssue (approved): %v", err)
		}
		if !dec.Approved {
			t.Fatalf("decision not approved: %+v", dec)
		}
		if gate.calls != 1 {
			t.Fatalf("gate consulted %d times, want exactly 1", gate.calls)
		}

		got := log.snapshot()
		if len(got) != 2 || got[0] != "gate" || got[1] != "keyop" {
			t.Fatalf("call order = %v, want [gate keyop] (gate strictly before key op, INV-A1)", got)
		}
		if log.countKeyOps() != 1 {
			t.Fatalf("observed %d key ops, want exactly 1", log.countKeyOps())
		}
	})

	t.Run("refused: gate consulted, ZERO key ops, refusal surfaced", func(t *testing.T) {
		log := &orderLog{}
		gate := &recordingGate{log: log, decision: IssuanceDecision{
			Approved:      false,
			RefusalRecord: []byte("signed-refusal"),
		}}
		s := NewServer(
			WithKeyFactory(newInstrumentedKeyFactory(log)),
			WithIssuanceGate(gate),
		)

		dec, err := s.gatedIssue(ctx, IssuancePreconditions{TenantID: "t1"}, newKeyOp(s, "issued-refused"))
		if err != nil {
			t.Fatalf("gatedIssue (refused) returned error, want nil with un-approved decision: %v", err)
		}
		if dec.Approved {
			t.Fatal("decision approved on a refusing gate")
		}
		if string(dec.RefusalRecord) != "signed-refusal" {
			t.Fatalf("refusal record = %q, want the gate's opaque refusal surfaced unaltered", dec.RefusalRecord)
		}
		if gate.calls != 1 {
			t.Fatalf("gate consulted %d times, want exactly 1", gate.calls)
		}
		if n := log.countKeyOps(); n != 0 {
			t.Fatalf("observed %d key ops on a refusing gate, want ZERO (INV-A1: no keyop without approval)", n)
		}
		got := log.snapshot()
		if len(got) != 1 || got[0] != "gate" {
			t.Fatalf("call order = %v, want [gate] only (no key op)", got)
		}

		// The refused issuance minted no key: the handle must not exist in the keystore.
		s.mu.Lock()
		_, exists := s.keys["issued-refused"]
		s.mu.Unlock()
		if exists {
			t.Fatal("a key was created for a refused issuance (INV-A1 violated)")
		}
	})

	t.Run("gate error: ZERO key ops, error surfaced", func(t *testing.T) {
		log := &orderLog{}
		sentinel := errors.New("gate boom")
		gate := &recordingGate{log: log, err: sentinel}
		s := NewServer(
			WithKeyFactory(newInstrumentedKeyFactory(log)),
			WithIssuanceGate(gate),
		)

		_, err := s.gatedIssue(ctx, IssuancePreconditions{TenantID: "t1"}, newKeyOp(s, "issued-error"))
		if !errors.Is(err, sentinel) {
			t.Fatalf("gatedIssue error = %v, want the gate error surfaced", err)
		}
		if n := log.countKeyOps(); n != 0 {
			t.Fatalf("observed %d key ops after a gate error, want ZERO", n)
		}
	})
}

// TestIssuanceGate_CoreOnlyAttachesNoGate proves INV-A10: the core issuance seam is
// generic and inert when nothing attaches. Two halves:
//   - in-process: with no gate attached, gatedIssue fails closed with
//     ErrNoIssuanceGate and performs no key op (the core-only build constructs the
//     signer exactly this way -- appendEEOptions is a no-op under -tags trstctl_core).
//   - build-level: the -tags trstctl_core build of cmd/trstctl-signer links ZERO ee/
//     packages, so no issuance gate (which lives in ee/) can be attached; asserted by
//     a go list -deps over the toolchain.
func TestIssuanceGate_CoreOnlyAttachesNoGate(t *testing.T) {
	ctx := context.Background()

	t.Run("in-process: no gate => fail-closed, no key op", func(t *testing.T) {
		// A default server (as the core-only build constructs it) attaches no gate.
		s := NewServer()
		if s.issuanceGate != nil {
			t.Fatal("a freshly constructed server has an issuance gate attached; the seam must be inert until WithIssuanceGate")
		}

		log := &orderLog{}
		// Instrument the key factory so we can prove the fail-closed path performs no
		// key op even though a key op was wired.
		s = NewServer(WithKeyFactory(newInstrumentedKeyFactory(log)))

		keyOp := func(_ context.Context, _ IssuanceDecision) error {
			_, err := s.GenerateSuccessorKey("must-not-be-created", crypto.ECDSAP256)
			return err
		}

		_, err := s.gatedIssue(ctx, IssuancePreconditions{TenantID: "t1"}, keyOp)
		if !errors.Is(err, ErrNoIssuanceGate) {
			t.Fatalf("gatedIssue with no gate = %v, want ErrNoIssuanceGate (fail-closed)", err)
		}
		if n := log.countKeyOps(); n != 0 {
			t.Fatalf("observed %d key ops with no gate attached, want ZERO (fail-closed, no keyop)", n)
		}
		s.mu.Lock()
		_, exists := s.keys["must-not-be-created"]
		s.mu.Unlock()
		if exists {
			t.Fatal("a key was created despite the fail-closed no-gate path")
		}

		// The direct consult point fails closed too.
		if _, err := s.verifyIssuancePreconditions(ctx, IssuancePreconditions{}); !errors.Is(err, ErrNoIssuanceGate) {
			t.Fatalf("verifyIssuancePreconditions with no gate = %v, want ErrNoIssuanceGate", err)
		}
	})

	t.Run("build-level: core-only signer links zero ee/", func(t *testing.T) {
		root := coreOnlyRepoRoot(t)
		cmd := exec.Command("go", "list", "-tags", "trstctl_core", "-deps", "./cmd/trstctl-signer")
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("go list -tags trstctl_core -deps ./cmd/trstctl-signer: %v\n%s", err, out)
		}
		for _, dep := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			dep = strings.TrimSpace(dep)
			if dep == "trstctl.com/trstctl/ee" || strings.HasPrefix(dep, "trstctl.com/trstctl/ee/") {
				t.Fatalf("core-only signer links ee/ package %q; the issuance gate (in ee/) must not be reachable in the core-only build (INV-A10)", dep)
			}
		}
	})
}

// coreOnlyRepoRoot returns the module root, derived from this test file's location
// (<root>/internal/signing/issuancegate_test.go), for shelling out to the toolchain.
func coreOnlyRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
