// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"strings"
	"time"
)

var spiffeQualificationOperations = []string{
	"FetchX509SVID",
	"FetchX509Bundles",
	"FetchJWTSVID",
	"FetchJWTBundles",
	"ValidateJWTSVID",
}

// SPIFFERuntimePosture is the credential-free state the composition root can
// prove about the SPIFFE Workload API for one authenticated tenant. It never
// carries SVIDs, key material, bundle bytes, audience values, or selector values.
type SPIFFERuntimePosture struct {
	Configured             bool
	Served                 bool
	Activated              bool
	TenantBound            bool
	TrustDomain            string
	SocketURI              string
	SocketReady            bool
	SocketOwnerOnly        bool
	SocketMode             string
	RegistrationEntryCount int
	IssuingPathReady       bool
	BulkheadReady          bool
	LocalSocketDeprecated  bool
	SupportedOperations    []string
}

// SPIFFEQualificationPosture reads only served process and socket metadata. It
// must not call the Workload API, signer, database, event log, outbox, or network.
type SPIFFEQualificationPosture func(context.Context, string) SPIFFERuntimePosture

// SPIFFEQualificationCheck is one exact readiness gate and its safe recovery.
type SPIFFEQualificationCheck struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Passed   bool   `json:"passed"`
	Detail   string `json:"detail"`
	Recovery string `json:"recovery,omitempty"`
}

// SPIFFEQualification is an effect-free operator review of the running Workload
// API. A stock workload client remains the final proof that credential delivery
// works; this response contains no workload credential material.
type SPIFFEQualification struct {
	CheckedAt              string                     `json:"checked_at"`
	Ready                  bool                       `json:"ready"`
	EffectFree             bool                       `json:"effect_free"`
	TrustDomain            string                     `json:"trust_domain"`
	SocketURI              string                     `json:"socket_uri"`
	Transport              string                     `json:"transport"`
	SocketMode             string                     `json:"socket_mode"`
	RegistrationEntryCount int                        `json:"registration_entry_count"`
	LocalSocketDeprecated  bool                       `json:"local_socket_deprecated"`
	SupportedOperations    []string                   `json:"supported_operations"`
	Checks                 []SPIFFEQualificationCheck `json:"checks"`
	PreviewWrites          []string                   `json:"preview_writes"`
	PreviewExternalEffects []string                   `json:"preview_external_effects"`
	PreviewSignerCalls     []string                   `json:"preview_signer_calls"`
	Proof                  []string                   `json:"proof"`
	Blockers               []string                   `json:"blockers"`
	ClientBoundary         string                     `json:"client_boundary"`
}

// WithSPIFFEQualificationPosture attaches the tenant-scoped, credential-free
// source. The API calls it only after authentication and tenant resolution.
func WithSPIFFEQualificationPosture(read SPIFFEQualificationPosture) Option {
	return func(c *config) { c.spiffeQualificationPosture = read }
}

func (a *API) qualifySPIFFE(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	posture := SPIFFERuntimePosture{SupportedOperations: append([]string(nil), spiffeQualificationOperations...)}
	if a.spiffeQualificationPosture != nil {
		posture = a.spiffeQualificationPosture(r.Context(), tenantID)
	}
	if len(posture.SupportedOperations) == 0 {
		posture.SupportedOperations = append([]string(nil), spiffeQualificationOperations...)
	}
	posture.TrustDomain = strings.TrimSpace(posture.TrustDomain)
	posture.SocketURI = strings.TrimSpace(posture.SocketURI)
	a.writeJSON(w, http.StatusOK, buildSPIFFEQualification(posture, time.Now().UTC()))
}

func buildSPIFFEQualification(posture SPIFFERuntimePosture, checkedAt time.Time) SPIFFEQualification {
	checks := []SPIFFEQualificationCheck{
		spiffeCheck("configured", "SPIFFE enabled", posture.Configured,
			"SPIFFE is enabled in startup configuration.",
			"Enable protocols.spiffe.enabled, set one tenant and trust domain, then restart the reviewed candidate."),
		spiffeCheck("workload-api-built", "Workload API built", posture.Served,
			"The running control plane assembled the SPIFFE Workload API.",
			"Repair the issuing CA, isolated signer, or SPIFFE startup error; do not substitute an unreviewed identity service."),
		spiffeCheck("activation", "Protocol profile active", posture.Activated,
			"The configured protocol profile allows the Workload API to serve.",
			"Activate the reviewed protocol profile, then re-run this check before starting a workload client."),
		spiffeCheck("tenant-binding", "Tenant binding", posture.TenantBound,
			"The Workload API is bound to this authenticated tenant.",
			"Set protocols.spiffe.tenant_id to this tenant and restart; never reuse another tenant's workload identity socket."),
		spiffeCheck("socket-listening", "Unix socket listening", posture.SocketReady,
			"The configured path is a live Unix domain socket.",
			"Repair the socket directory, mount, permissions, or server lifecycle, then confirm the exact path again."),
		spiffeCheck("socket-permissions", "Socket owner-only", posture.SocketOwnerOnly,
			"The socket denies group and other access.",
			"Restore owner-only socket permissions and workload-specific mount boundaries before allowing clients."),
		spiffeCheck("registration-policy", "Registration policy attached", posture.RegistrationEntryCount > 0,
			"At least one registration entry can bind an approved workload to a SPIFFE ID.",
			"Add an explicit registration entry with the narrowest selectors and node scope; never make an unmatched workload eligible."),
		spiffeCheck("issuing-path", "Isolated issuing path", posture.IssuingPathReady,
			"X.509 and JWT issuance route through the served CA and isolated signer boundary.",
			"Repair signer health, issuing CA material, or the workload issuer before retrying a client."),
		spiffeCheck("bounded-capacity", "Bounded workload capacity", posture.BulkheadReady,
			"Workload requests use the bounded protocol worker pool.",
			"Restore the protocol bulkhead before retrying so workload traffic cannot starve the control plane API."),
	}
	blockers := make([]string, 0)
	ready := true
	for _, check := range checks {
		if !check.Passed {
			ready = false
			blockers = append(blockers, check.Label+": "+check.Recovery)
		}
	}
	return SPIFFEQualification{
		CheckedAt: checkedAt.Format(time.RFC3339), Ready: ready, EffectFree: true,
		TrustDomain: posture.TrustDomain, SocketURI: posture.SocketURI, Transport: "unix", SocketMode: posture.SocketMode,
		RegistrationEntryCount: posture.RegistrationEntryCount, LocalSocketDeprecated: posture.LocalSocketDeprecated,
		SupportedOperations: append([]string(nil), posture.SupportedOperations...), Checks: checks,
		PreviewWrites: []string{}, PreviewExternalEffects: []string{}, PreviewSignerCalls: []string{},
		Proof: []string{
			"This qualification reads only in-memory served posture and Unix socket file metadata for the authenticated tenant.",
			"It does not dial the Workload API or request, mint, validate, return, or store an SVID, key, certificate, or trust bundle.",
			"It does not call the signer, event log, outbox, database, or network; a stock workload client supplies the final wire proof.",
		},
		Blockers:       blockers,
		ClientBoundary: "Workloads fetch short-lived credentials from their local Unix socket; operators review readiness here without receiving workload key material.",
	}
}

func spiffeCheck(id, label string, passed bool, success, recovery string) SPIFFEQualificationCheck {
	detail := success
	recoveryText := ""
	if !passed {
		detail = "This gate is not ready in the running process."
		recoveryText = recovery
	}
	return SPIFFEQualificationCheck{ID: id, Label: label, Passed: passed, Detail: detail, Recovery: recoveryText}
}
