// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"strings"
	"time"
)

// CMPRuntimePosture is the deliberately secret-free state the composition root
// can prove about the CMP mount for one authenticated tenant. It carries no
// configuration paths, trust-anchor bytes, certificates, private keys, CSRs, or
// PKIMessages. The API turns these booleans into operator-facing checks so the
// composition root never owns product copy.
type CMPRuntimePosture struct {
	Configured             bool
	Served                 bool
	Endpoint               string
	TenantBound            bool
	RATransportReady       bool
	ClientTrustAnchorCount int
	IssuingPathReady       bool
	ProfileName            string
	ProfileReady           bool
	BindingMode            string
	BulkheadReady          bool
}

// CMPQualificationPosture reads in-memory served state. It must not perform a
// network call, database query, signer operation, event append, or outbox write.
// Keeping this as a function rather than a mutable service makes the read-only
// boundary visible at the API attachment seam.
type CMPQualificationPosture func(context.Context, string) CMPRuntimePosture

// CMPQualificationCheck is one exact readiness gate and its safe recovery.
type CMPQualificationCheck struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Passed   bool   `json:"passed"`
	Detail   string `json:"detail"`
	Recovery string `json:"recovery,omitempty"`
}

// CMPQualification is an effect-free review of the running CMP endpoint. It
// proves only what the server can know without manufacturing a client identity
// or sending a PKIMessage. A stock client enrollment remains the final wire proof.
type CMPQualification struct {
	CheckedAt              string                  `json:"checked_at"`
	Ready                  bool                    `json:"ready"`
	EffectFree             bool                    `json:"effect_free"`
	Endpoint               string                  `json:"endpoint"`
	Profile                string                  `json:"profile"`
	BindingMode            string                  `json:"binding_mode"`
	ClientTrustAnchorCount int                     `json:"client_trust_anchor_count"`
	Checks                 []CMPQualificationCheck `json:"checks"`
	PreviewWrites          []string                `json:"preview_writes"`
	PreviewExternalEffects []string                `json:"preview_external_effects"`
	PreviewSignerCalls     []string                `json:"preview_signer_calls"`
	Proof                  []string                `json:"proof"`
	Blockers               []string                `json:"blockers"`
}

// WithCMPQualificationPosture attaches the secret-free, in-memory CMP posture
// reader. The supplied function is called only after authentication and tenant
// resolution; it receives the authenticated tenant and no caller-controlled
// resource identifier.
func WithCMPQualificationPosture(read CMPQualificationPosture) Option {
	return func(c *config) { c.cmpQualificationPosture = read }
}

func (a *API) qualifyCMP(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	posture := CMPRuntimePosture{Endpoint: "/cmp", BindingMode: "subject-bound", ProfileName: "default"}
	if a.cmpQualificationPosture != nil {
		posture = a.cmpQualificationPosture(r.Context(), tenantID)
	}
	if strings.TrimSpace(posture.Endpoint) == "" {
		posture.Endpoint = "/cmp"
	}
	if strings.TrimSpace(posture.ProfileName) == "" {
		posture.ProfileName = "default"
	}
	if strings.TrimSpace(posture.BindingMode) == "" {
		posture.BindingMode = "subject-bound"
	}
	out := buildCMPQualification(posture, time.Now().UTC())
	a.writeJSON(w, http.StatusOK, out)
}

func buildCMPQualification(posture CMPRuntimePosture, checkedAt time.Time) CMPQualification {
	checks := []CMPQualificationCheck{
		cmpCheck("configured", "CMP enabled", posture.Configured,
			"CMP is enabled in startup configuration.",
			"Enable protocols.cmp.enabled and restart the reviewed deployment candidate."),
		cmpCheck("endpoint-mounted", "CMP endpoint mounted", posture.Served,
			"The running control plane owns POST "+posture.Endpoint+".",
			"Repair the issuing CA, signer, or protocol startup failure; do not route around the missing mount."),
		cmpCheck("tenant-binding", "Tenant binding", posture.TenantBound,
			"The CMP mount is bound to this authenticated tenant.",
			"Set protocols.cmp.tenant_id to this tenant and restart; never reuse another tenant's enrollment mount."),
		cmpCheck("ra-transport", "RA transport identity", posture.RATransportReady,
			"The sealed CMP response-protection identity is loaded in memory.",
			"Configure the sealed protocols.ra_key_file on shared protected storage and restart; never paste key bytes into the console."),
		cmpCheck("client-trust", "Client protection trust", posture.ClientTrustAnchorCount > 0,
			"At least one operator-approved client protection trust anchor is loaded.",
			"Configure protocols.cmp_client_trust_anchor_file with the approved client or RA chain and restart; anonymous CMP enrollment stays refused."),
		cmpCheck("issuing-path", "Isolated issuing path", posture.IssuingPathReady,
			"The event-sourced issuer and isolated signer path are attached.",
			"Repair signer health, issuing CA material, event log, or idempotency wiring before allowing a client retry."),
		cmpCheck("profile-policy", "Issuing profile", posture.ProfileReady,
			"The server can enforce the "+posture.ProfileName+" certificate profile.",
			"Repair the configured issuing profile and policy; do not weaken name, EKU, validity, or algorithm constraints."),
		cmpCheck("bounded-capacity", "Bounded enrollment capacity", posture.BulkheadReady,
			"CMP enrollment uses the bounded protocol worker pool.",
			"Restore the protocol bulkhead before retrying so enrollment load cannot starve the control plane API."),
	}
	blockers := make([]string, 0)
	ready := true
	for _, check := range checks {
		if check.Passed {
			continue
		}
		ready = false
		blockers = append(blockers, check.Label+": "+check.Recovery)
	}
	return CMPQualification{
		CheckedAt: checkedAt.Format(time.RFC3339), Ready: ready, EffectFree: true,
		Endpoint: posture.Endpoint, Profile: posture.ProfileName, BindingMode: posture.BindingMode,
		ClientTrustAnchorCount: posture.ClientTrustAnchorCount,
		Checks:                 checks, PreviewWrites: []string{}, PreviewExternalEffects: []string{}, PreviewSignerCalls: []string{},
		Proof: []string{
			"This qualification reads only in-memory server posture for the authenticated tenant.",
			"It does not create, parse, send, or store a CSR, PKIMessage, protection credential, certificate, or private key.",
			"It does not call the signer, event log, outbox, database, or network; only POST /cmp can attempt enrollment.",
		},
		Blockers: blockers,
	}
}

func cmpCheck(id, label string, passed bool, success, recovery string) CMPQualificationCheck {
	detail := success
	recoveryText := ""
	if !passed {
		detail = "This gate is not ready in the running process."
		recoveryText = recovery
	}
	return CMPQualificationCheck{ID: id, Label: label, Passed: passed, Detail: detail, Recovery: recoveryText}
}
