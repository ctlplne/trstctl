// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"runtime"
	"time"
)

// B-5: /admin/system rendered edition, support, and scale POSTURE — the things
// the product claims — but not the readout an operator actually wants when
// something looks wrong: which build is running, how long it has been up, and
// whether the spine (database, event log, signer) is reachable right now. That
// answer existed only on /healthz and /readyz, which are unauthenticated
// infrastructure probes shaped for a load balancer, not for a console.
//
// Everything here is process identity and liveness. No tenant data, no
// configuration values, and deliberately no addresses or DSNs: a component is
// reachable or it is not, and an operator with a console session may know
// that much without learning where the dependency lives.

// SystemDependency is one spine component's live reachability.
type SystemDependency struct {
	Name string `json:"name"`
	// Ready is the probe result. Error carries the failure reason, already
	// sanitized by the probe (never a DSN or address).
	Ready bool   `json:"ready"`
	Error string `json:"error,omitempty"`
}

// SystemReadoutProvider is the server-side seam: internal/server owns the
// build stamp, start time, and the readiness checks, and hands this API a
// closure rather than its internals.
type SystemReadoutProvider func() SystemReadout

// IdempotencyResultProtectionProvider reads counts for the authenticated
// tenant plus the fleet-wide codec ratchet. Result bytes never enter this seam.
type IdempotencyResultProtectionProvider func(context.Context, string) (IdempotencyResultProtectionReadout, error)

// IdempotencyResultProtectionReadout is the operator-facing custody posture for
// cached mutation responses. Failure and recovery are deliberately bounded,
// pre-written guidance: raw database errors can contain deployment details.
type IdempotencyResultProtectionReadout struct {
	State                  string `json:"state"`
	FleetReady             bool   `json:"fleet_ready"`
	SealedOnlyFloor        bool   `json:"sealed_only_floor"`
	RawV0Remaining         int64  `json:"raw_v0_remaining"`
	LegacyDynamicRemaining int64  `json:"legacy_dynamic_remaining"`
	SealedResults          int64  `json:"sealed_results"`
	PendingResults         int64  `json:"pending_results"`
	IndeterminateResults   int64  `json:"indeterminate_results"`
	Failure                string `json:"failure,omitempty"`
	Recovery               string `json:"recovery"`
}

// SystemReadout is the served answer to "what is running, and is it healthy".
type SystemReadout struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	// StartedAt and UptimeSeconds answer "did this just restart?" — the first
	// question after unexplained behavior.
	StartedAt     time.Time `json:"started_at"`
	UptimeSeconds int64     `json:"uptime_seconds"`
	// SignerMode is "child", "external", or "none": AN-4 says the signer is a
	// separate process, and an operator should be able to confirm which
	// topology is live without reading the config.
	SignerMode string `json:"signer_mode"`
	// FIPSModuleActive reports whether the Go FIPS 140-3 module is routing
	// crypto/* in this process (artifact-gated by `make fips-build`).
	FIPSModuleActive   bool                               `json:"fips_module_active"`
	Dependencies       []SystemDependency                 `json:"dependencies"`
	IdempotencyResults IdempotencyResultProtectionReadout `json:"idempotency_results"`
	// Deployment is the issued/delivered/verified roll-up (epic D3).
	//
	// It sits on the health readout deliberately. Every other health number
	// here describes this process; this one describes the estate, and it is the
	// only one sourced from observations of the outside world rather than from
	// trstctl's own records.
	Deployment DeploymentTriState `json:"deployment"`
}

// DeploymentTriState is how many targets are delivered, verified, failing
// verification, and unverified (epic D3).
//
// Delivered and verified are counted separately because they are different
// claims. A connector applying a credential is the pipeline's account of what
// it did; an endpoint serving that credential is what a client actually gets,
// and only a handshake establishes the second. A health surface that counted
// deliveries would be reporting intentions.
type DeploymentTriState struct {
	Delivered    int `json:"delivered"`
	Verified     int `json:"verified"`
	VerifyFailed int `json:"verify_failed"`
	// Unverified is delivered targets nobody has probed. Neither a failure nor
	// a pass — and on a fresh install every target is here, which is the
	// correct starting picture rather than a discouraging one.
	Unverified int `json:"unverified"`
	// VerifiedPercent is of DELIVERED targets, so it answers "of what we have
	// deployed, how much is confirmed live". Zero delivered targets yields zero
	// rather than 100: a percentage over nothing is the most misleading number
	// a health surface can print.
	VerifiedPercent int `json:"verified_percent"`
}

// getPlatformSystem returns the readout, or served=false shaped data when no
// provider is wired — the same discipline as the bulkhead route: answer
// truthfully rather than 404 on an assembly that does not carry it.
func (a *API) getPlatformSystem(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	protection := IdempotencyResultProtectionReadout{
		State:    "unavailable",
		Failure:  "Idempotency result protection status is not wired.",
		Recovery: "Run the default control-plane binary with its PostgreSQL store and tenant result protector configured.",
	}
	if a.idemProtection != nil {
		var err error
		protection, err = a.idemProtection(r.Context(), tenantID)
		if err != nil {
			protection = IdempotencyResultProtectionReadout{
				State:    "failed",
				Failure:  "Idempotency result protection status could not be read.",
				Recovery: "Check PostgreSQL readiness and the tenant seal wrapper, then retry this status read.",
			}
		}
	}
	if a.systemReadout == nil {
		a.writeJSON(w, http.StatusOK, SystemReadout{GoVersion: runtime.Version(), Dependencies: []SystemDependency{}, IdempotencyResults: protection})
		return
	}
	readout := a.systemReadout()
	readout.IdempotencyResults = protection
	if readout.GoVersion == "" {
		readout.GoVersion = runtime.Version()
	}
	if readout.Dependencies == nil {
		readout.Dependencies = []SystemDependency{}
	}
	// D3: the estate's deployment truth, counted by what was VERIFIED rather
	// than by what was delivered. A read failure leaves the zero value rather
	// than omitting the block: zeroes read as "nothing confirmed", which is the
	// honest reading when the count could not be taken.
	if a.store != nil && tenantID != "" {
		if tri, err := a.store.SummarizeDeploymentTriState(r.Context(), tenantID); err == nil {
			readout.Deployment = DeploymentTriState{
				Delivered: tri.Delivered, Verified: tri.Verified,
				VerifyFailed: tri.VerifyFailed, Unverified: tri.Unverified,
			}
			if tri.Delivered > 0 {
				readout.Deployment.VerifiedPercent = tri.Verified * 100 / tri.Delivered
			}
		}
	}
	a.writeJSON(w, http.StatusOK, readout)
}
