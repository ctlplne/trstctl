// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"strings"
	"time"
)

const defaultTSAPolicyOID = "1.3.6.1.4.1.59551.2.1"

// TSARuntimePosture is the secret-free state the composition root can prove
// about the RFC 3161 responder for one authenticated tenant. It deliberately
// excludes certificate bytes, file paths, signer handles, keys, and request
// bodies. The qualification route only reads these booleans; POST /tsa remains
// the sole path that can ask the isolated signer to issue a timestamp.
type TSARuntimePosture struct {
	Configured             bool
	Served                 bool
	Activated              bool
	Endpoint               string
	TenantBound            bool
	StableCertificateReady bool
	SignerReady            bool
	AuditReady             bool
	BulkheadReady          bool
	PolicyOID              string
}

// TSAQualificationPosture reads in-memory served state. It must not read a
// request body, contact the signer, query storage, append an event, or call the
// network. The authenticated tenant is its only caller-supplied input.
type TSAQualificationPosture func(context.Context, string) TSARuntimePosture

// TSAQualificationCheck is one exact readiness gate plus its safe recovery.
type TSAQualificationCheck struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Passed   bool   `json:"passed"`
	Detail   string `json:"detail"`
	Recovery string `json:"recovery,omitempty"`
}

// TSAQualification is an effect-free review of the running timestamp service.
// It does not claim wire interoperability: the operator proves that separately
// by sending a TimeStampReq to POST /tsa and verifying the TimeStampResp with a
// stock RFC 3161 client such as OpenSSL.
type TSAQualification struct {
	CheckedAt              string                  `json:"checked_at"`
	Ready                  bool                    `json:"ready"`
	EffectFree             bool                    `json:"effect_free"`
	Endpoint               string                  `json:"endpoint"`
	PolicyOID              string                  `json:"policy_oid"`
	Checks                 []TSAQualificationCheck `json:"checks"`
	PreviewWrites          []string                `json:"preview_writes"`
	PreviewExternalEffects []string                `json:"preview_external_effects"`
	PreviewSignerCalls     []string                `json:"preview_signer_calls"`
	Proof                  []string                `json:"proof"`
	Blockers               []string                `json:"blockers"`
}

// WithTSAQualificationPosture attaches the tenant-scoped, credential-free
// readiness reader used by the authenticated console workflow.
func WithTSAQualificationPosture(read TSAQualificationPosture) Option {
	return func(c *config) { c.tsaQualificationPosture = read }
}

func (a *API) qualifyTSA(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	posture := TSARuntimePosture{Endpoint: "/tsa", PolicyOID: defaultTSAPolicyOID}
	if a.tsaQualificationPosture != nil {
		posture = a.tsaQualificationPosture(r.Context(), tenantID)
	}
	if strings.TrimSpace(posture.Endpoint) == "" {
		posture.Endpoint = "/tsa"
	}
	if strings.TrimSpace(posture.PolicyOID) == "" {
		posture.PolicyOID = defaultTSAPolicyOID
	}
	a.writeJSON(w, http.StatusOK, buildTSAQualification(posture, time.Now().UTC()))
}

func buildTSAQualification(posture TSARuntimePosture, checkedAt time.Time) TSAQualification {
	checks := []TSAQualificationCheck{
		tsaCheck("configured", "TSA enabled", posture.Configured,
			"TSA is enabled in startup configuration.",
			"Enable protocols.tsa.enabled, bind protocols.tsa.tenant_id, configure protocols.tsa_cert_file, and restart the reviewed candidate."),
		tsaCheck("endpoint-mounted", "TSA endpoint mounted", posture.Served,
			"The running control plane owns POST "+posture.Endpoint+".",
			"Repair protocol startup; do not route around a missing responder or substitute the web application fallback."),
		tsaCheck("activation", "Protocol profile active", posture.Activated,
			"The configured protocol profile allows the timestamp responder to serve.",
			"Activate the reviewed protocol profile, then re-run this check before sending a timestamp request."),
		tsaCheck("tenant-binding", "Tenant binding", posture.TenantBound,
			"The TSA mount is bound to this authenticated tenant.",
			"Bind protocols.tsa.tenant_id to this tenant and restart; never share a timestamp authority across tenant boundaries implicitly."),
		tsaCheck("stable-certificate", "Stable TSA certificate", posture.StableCertificateReady,
			"The responder loaded a stable timestamping certificate whose public key matches the signer-held key.",
			"Restore the protected protocols.tsa_cert_file or intentionally reprovision the signer key and certificate together; do not accept a key/certificate mismatch."),
		tsaCheck("signer", "Isolated timestamp signer", posture.SignerReady,
			"The timestamp key is reachable through the isolated signer process.",
			"Restore the isolated signer connection; never move the TSA key into the control-plane process."),
		tsaCheck("audit", "Immutable issuance audit", posture.AuditReady,
			"Accepted timestamps can append tsa.timestamp.issued to the event-backed audit ledger.",
			"Restore the event log before timestamping; do not issue untracked timestamp tokens."),
		tsaCheck("bounded-capacity", "Bounded responder capacity", posture.BulkheadReady,
			"The responder is protected by the bounded protocol HTTP worker pool.",
			"Restore the API/protocol bulkhead before retrying so timestamp load cannot starve the control plane."),
	}
	ready := true
	blockers := make([]string, 0)
	for _, check := range checks {
		if check.Passed {
			continue
		}
		ready = false
		blockers = append(blockers, check.Label+": "+check.Recovery)
	}
	return TSAQualification{
		CheckedAt: checkedAt.Format(time.RFC3339), Ready: ready, EffectFree: true,
		Endpoint: posture.Endpoint, PolicyOID: posture.PolicyOID, Checks: checks,
		PreviewWrites: []string{}, PreviewExternalEffects: []string{}, PreviewSignerCalls: []string{},
		Proof: []string{
			"This qualification reads only in-memory served posture for the authenticated tenant.",
			"It does not create, parse, send, sign, store, or return a TimeStampReq, TimeStampResp, certificate, token, or private key.",
			"It does not call the signer, event log, database, outbox, filesystem, or network; only POST /tsa can issue a timestamp.",
		},
		Blockers: blockers,
	}
}

func tsaCheck(id, label string, passed bool, success, recovery string) TSAQualificationCheck {
	detail := success
	recoveryText := ""
	if !passed {
		detail = "This gate is not ready in the running process."
		recoveryText = recovery
	}
	return TSAQualificationCheck{ID: id, Label: label, Passed: passed, Detail: detail, Recovery: recoveryText}
}
