package bulkhead

import "sort"

// Subsystem names for the parts of the control plane that own a bulkhead today.
// New subsystems register their own pool as they land.
const (
	SubsystemAPI         = "api"
	SubsystemProjections = "projections"
	SubsystemOutbox      = "outbox"
	SubsystemSigning     = "signing"
	// SubsystemQuery is the bounded pool for heavy, per-request O(inventory) read
	// families — the credential-graph and risk-scoring endpoints (SPINE-005). Routing
	// them to their own pool keeps a burst of expensive graph/risk builds from
	// occupying the API workers and starving cheap CRUD (and /auth, /enroll) on the
	// shared SubsystemAPI pool (AN-7 fairness within the served surface).
	SubsystemQuery = "query"
	// SubsystemPolicy is the bounded pool the OPA/Rego policy engine evaluates on
	// (AN-7), so a policy-evaluation storm on the served issue/deploy/revoke gate
	// (EXC-WIRE-03) cannot starve the API workers — and a saturated policy pool sheds
	// fast and fails closed (a shed decision is a deny) rather than blocking issuance.
	SubsystemPolicy = "policy"
	// SubsystemProtocols is the bounded pool the served issuance protocols (ACME,
	// EST, SCEP, CMP, SPIFFE, SSH; EXC-WIRE-02) run their enrollment work on (AN-7),
	// so an enrollment burst from a fleet of devices/workloads sheds fast and can
	// never starve the API workers, liveness/readiness, or the signer. A saturated
	// protocols pool returns a structured "busy" (HTTP 503 / gRPC Unavailable).
	SubsystemProtocols = "protocols"
)

// Set is a collection of named, isolated pools — one per subsystem. Submitting to
// one subsystem can never consume another's capacity (AN-7).
type Set struct {
	pools map[string]*Pool
}

// NewSet starts a pool for each config, keyed by config Name.
func NewSet(cfgs ...Config) *Set {
	s := &Set{pools: make(map[string]*Pool, len(cfgs))}
	for _, c := range cfgs {
		s.pools[c.Name] = New(c)
	}
	return s
}

// Default returns a Set with a conservatively sized, isolated pool for each
// subsystem that exists so far. The sizes are starting points, tunable per
// deployment.
func Default() *Set {
	return NewSet(
		Config{Name: SubsystemAPI, Workers: 8, Queue: 256},
		Config{Name: SubsystemProjections, Workers: 2, Queue: 128},
		Config{Name: SubsystemOutbox, Workers: 4, Queue: 256},
		Config{Name: SubsystemSigning, Workers: 4, Queue: 64},
		// The heavy read pool (SPINE-005) is sized smaller than the CRUD pool: it caps
		// how many concurrent O(inventory) graph/risk builds run, so they shed fast
		// under load instead of monopolizing capacity — while the cheap CRUD pool stays
		// free. A modest queue absorbs short bursts.
		Config{Name: SubsystemQuery, Workers: 4, Queue: 64},
		// The policy-engine pool (EXC-WIRE-03/AN-7): served issue/deploy/revoke gate
		// evaluations run here, isolated from the API workers, and shed fast (fail
		// closed) when saturated. Rego evaluation is CPU-bound and short, so a few
		// workers with a small queue suffice.
		Config{Name: SubsystemPolicy, Workers: 4, Queue: 64},
		// The served issuance-protocols pool (EXC-WIRE-02/AN-7): ACME/EST/SCEP/CMP/
		// SPIFFE/SSH enrollment work runs here, isolated from the API workers, so a
		// device/workload enrollment burst sheds rather than starving the rest of the
		// control plane. Sized like the CRUD pool's heavier siblings — enrollment is a
		// signer round-trip, so a generous queue absorbs bursts while workers bound
		// concurrency against the signer.
		Config{Name: SubsystemProtocols, Workers: 8, Queue: 256},
	)
}

// Pool returns the named pool, or nil if no such subsystem is registered.
func (s *Set) Pool(name string) *Pool { return s.pools[name] }

// Submit runs task on the named subsystem's pool. It returns *Rejected if the
// subsystem is unknown or its pool is saturated.
func (s *Set) Submit(name string, task func()) error {
	p, ok := s.pools[name]
	if !ok {
		return &Rejected{Pool: name, Reason: ReasonUnknown}
	}
	return p.Submit(task)
}

// Close shuts down every pool, draining queued work.
func (s *Set) Close() {
	for _, p := range s.pools {
		p.Close()
	}
}

// Stats returns a snapshot of every pool's stats, ordered by subsystem name.
func (s *Set) Stats() []Stats {
	out := make([]Stats, 0, len(s.pools))
	for _, p := range s.pools {
		out = append(out, p.Stats())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
