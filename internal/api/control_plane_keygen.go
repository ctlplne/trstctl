// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"time"
	"trstctl.com/trstctl/internal/authz"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Owner decision 2026-10-24 (A120/A130/A132): the tenant's switch over
// control-plane key generation. The three generators stay in the product;
// each tenant decides whether the control plane may make a subject private key
// on a requester's behalf. New tenants start with it off.

// controlPlaneKeygenPaths are the generators the switch governs.
var controlPlaneKeygenPaths = []string{
	"identity issuance without a CSR, and the renewal or rotation of an identity whose key the control plane generated",
	"PKI-secret issuance by common name, including the Vault-compatible pki/issue route",
	"X.509-SVIDs from the compatibility Workload API socket served by the control plane",
	"Kubernetes TLS auto-issuance from a k8s_ingress_gateway discovery source",
	"the reissue step of a PQC migration run started before host-csr migration",
}

// refuseControlPlaneKeygen is the switch's check for the API's own key
// generators. A tenant that predates the switch and has not been decided yet
// keeps them.
func (a *API) refuseControlPlaneKeygen(ctx context.Context, tenantID, replacement string) error {
	policy, found, err := a.store.ControlPlaneKeygenFor(ctx, tenantID)
	if err != nil {
		return err
	}
	if found && !policy.Enabled {
		return orchestrator.ControlPlaneKeygenOff(replacement)
	}
	return nil
}

const controlPlaneKeygenGuidance = "With control-plane key generation off, each governed path is refused before a " +
	"key exists and names its replacement: an identity issuance needs a CSR (subject_csr_pem) or an agent-executed " +
	"target so the host generates the key, and its renewal fails its rotation run with the same reason; a PKI secret " +
	"needs csr_pem, and the Vault-compatible pki/issue route sends callers to pki/sign; the compatibility Workload API " +
	"socket refuses X.509-SVIDs and names the host agent's socket; Kubernetes TLS auto-issuance refuses each resource " +
	"and names cert-manager; an older PQC migration's reissue waits and names host-csr migration. Turning it on lets the " +
	"control plane generate subject keys again; each use still records an issuance.server_side_keygen or " +
	"spiffe.workload_api.local_socket_used event."

// controlPlaneKeygenRoutes serves the tenant's switch (owner decision
// 2026-10-24, A120/A130/A132).
func (a *API) controlPlaneKeygenRoutes() []route {
	return []route{
		{method: "GET", path: "/api/v1/tenant/key-generation", opID: "getControlPlaneKeygen", summary: "Read whether the control plane may generate subject private keys for this tenant, who decided and why", handler: a.getControlPlaneKeygen, resSchema: "ControlPlaneKeygen", successCode: "200", perm: authz.AccessRead},
		{method: "PUT", path: "/api/v1/tenant/key-generation", opID: "putControlPlaneKeygen", summary: "Turn control-plane key generation on or off for this tenant, with a reason", handler: a.putControlPlaneKeygen, reqSchema: "ControlPlaneKeygenInput", resSchema: "ControlPlaneKeygen", successCode: "200", mutation: true, perm: authz.AccessWrite},
	}
}

type controlPlaneKeygenBody struct {
	Enabled *bool  `json:"enabled"`
	Reason  string `json:"reason"`
}

type controlPlaneKeygenResponse struct {
	Decided  bool                              `json:"decided"`
	Enabled  bool                              `json:"enabled"`
	Source   string                            `json:"source,omitempty"`
	Reason   string                            `json:"reason,omitempty"`
	SetBy    string                            `json:"set_by,omitempty"`
	SetAt    string                            `json:"set_at,omitempty"`
	Evidence *store.ControlPlaneKeygenEvidence `json:"evidence,omitempty"`
	// ControlPlaneIdentities counts active certificates whose key the control
	// plane generated: their renewals need control-plane key generation.
	ControlPlaneIdentities int64    `json:"control_plane_identities"`
	Paths                  []string `json:"paths"`
	Guidance               string   `json:"guidance"`
}

func controlPlaneKeygenFrom(p store.ControlPlaneKeygenPolicy, found bool, active int64) controlPlaneKeygenResponse {
	out := controlPlaneKeygenResponse{Decided: found, Enabled: !found || p.Enabled, Source: p.Source, Reason: p.Reason,
		SetBy: p.SetBy, Evidence: p.Evidence, ControlPlaneIdentities: active, Paths: controlPlaneKeygenPaths,
		Guidance: controlPlaneKeygenGuidance}
	if !p.SetAt.IsZero() {
		out.SetAt = p.SetAt.UTC().Format(time.RFC3339)
	}
	return out
}

func (a *API) getControlPlaneKeygen(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	policy, found, err := a.store.ControlPlaneKeygenFor(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	active, err := a.store.ActiveControlPlaneKeyCertificates(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, controlPlaneKeygenFrom(policy, found, active))
}

//trstctl:mutation
func (a *API) putControlPlaneKeygen(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var body controlPlaneKeygenBody
		if err := decodeJSON(r, &body); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if body.Enabled == nil {
			return 0, nil, errStatus(http.StatusBadRequest, "enabled is required")
		}
		set, err := a.orch.SetControlPlaneKeygen(ctx, tenantID, projections.ControlPlaneKeygenSet{
			Enabled: *body.Enabled, Source: store.ControlPlaneKeygenSourceOperator, Reason: body.Reason, SetBy: principalSubject(ctx),
		})
		if errors.Is(err, orchestrator.ErrControlPlaneKeygenReason) {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		if err != nil {
			return 0, nil, err
		}
		active, err := a.store.ActiveControlPlaneKeyCertificates(ctx, tenantID)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, controlPlaneKeygenFrom(store.ControlPlaneKeygenPolicy{TenantID: tenantID, Enabled: set.Enabled,
			Source: set.Source, Reason: set.Reason, SetBy: set.SetBy, SetAt: set.SetAt}, true, active), nil
	})
}
