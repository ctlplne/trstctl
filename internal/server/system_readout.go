// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"runtime"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/buildinfo"
	"trstctl.com/trstctl/internal/crypto"
)

// B-5: the server owns the facts the console's system readout needs — the
// build stamp, when this process started, which signer topology is live, and
// the readiness probes (including whether the ordered projection is poisoned) —
// so it builds the readout and hands the API a closure rather than its internals.
//
// The probes here are the SAME ones /readyz runs. Reusing them means the
// console can never disagree with the load balancer about whether the spine
// can serve trustworthy read state, which is the failure mode that makes an
// operator distrust both.

// systemReadoutTimeout bounds one readout so a hung dependency degrades this
// endpoint instead of hanging the caller. It is deliberately shorter than a
// typical HTTP client timeout.
const systemReadoutTimeout = 3 * time.Second

// systemDependencyOrder makes the operator readout deterministic. Keep the
// source-of-truth path together (database -> event log -> projection), then the
// isolated signer. Missing optional dependencies are skipped in place.
var systemDependencyOrder = [...]string{"db", "nats", "projection", "signer"}

func (s *Server) systemReadout(ctx context.Context) api.SystemReadout {
	readout := api.SystemReadout{
		Version:          buildinfo.Version(),
		Commit:           buildinfo.Commit(),
		BuildDate:        buildinfo.Date(),
		GoVersion:        runtime.Version(),
		StartedAt:        s.startedAt,
		SignerMode:       s.signerMode(),
		FIPSModuleActive: crypto.FIPSEnabled(),
		Dependencies:     []api.SystemDependency{},
	}
	if !s.startedAt.IsZero() {
		readout.UptimeSeconds = int64(time.Since(s.startedAt).Seconds())
	}
	if s.readiness == nil {
		return readout
	}
	probeCtx, cancel := context.WithTimeout(ctx, systemReadoutTimeout)
	defer cancel()
	_, results := s.readiness.Evaluate(probeCtx)
	// Stable order: the readiness map is unordered, and a console table that
	// reshuffles on every poll is unreadable.
	for _, name := range systemDependencyOrder {
		status, ok := results[name]
		if !ok {
			continue
		}
		dep := api.SystemDependency{Name: name, Ready: status == "ok"}
		if !dep.Ready {
			dep.Error = status
		}
		readout.Dependencies = append(readout.Dependencies, dep)
	}
	return readout
}

// signerMode reports the live AN-4 topology rather than the configured intent:
// "child" when this process supervises the signer, "external" when it dials a
// separately deployed one, and "none" when no signer is attached.
func (s *Server) signerMode() string {
	if s.signer == nil {
		return "none"
	}
	switch s.signerTopology {
	case "external":
		return "external"
	case "child", "":
		// Empty is the compatibility default for tests and direct Build callers.
		// Production always supplies the topology opened by openRunSigner.
		return "child"
	default:
		// Unknown topology is not promoted to an operator claim.
		return "none"
	}
}
