// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
	"trstctl.com/trstctl/internal/store"
)

type ACMEDNS01ProviderCatalogItem struct {
	Name                      string   `json:"name"`
	DisplayName               string   `json:"display_name"`
	Kind                      string   `json:"kind"`
	Served                    bool     `json:"served"`
	PropagationPreflight      bool     `json:"propagation_preflight"`
	Conformance               string   `json:"conformance"`
	AdmissionState            string   `json:"admission_state"`
	Provenance                string   `json:"provenance"`
	CredentialReferenceFields []string `json:"credential_reference_fields"`
	SecretFields              []string `json:"secret_fields"`
	Capabilities              []string `json:"capabilities"`
	ProviderPackage           string   `json:"provider_package"`
	Notes                     string   `json:"notes"`
}

type dns01ProviderCatalogResponse struct {
	Items []ACMEDNS01ProviderCatalogItem `json:"items"`
}

type dns01ProviderConfigRequest struct {
	Name             string          `json:"name"`
	Provider         string          `json:"provider"`
	Zone             string          `json:"zone,omitempty"`
	ChallengeDomain  string          `json:"challenge_domain,omitempty"`
	DelegationTarget string          `json:"delegation_target,omitempty"`
	CredentialRefs   json.RawMessage `json:"credential_refs,omitempty"`
	Config           json.RawMessage `json:"config,omitempty"`
	CAAIssuerDomain  string          `json:"caa_issuer_domain,omitempty"`
	AllowedMethods   []string        `json:"allowed_methods,omitempty"`
	AllowWildcards   bool            `json:"allow_wildcards,omitempty"`
	// AllowUpstreamDV permits this config to publish challenge records for
	// UPSTREAM domain validation against an external CA (epic B7). Off unless
	// an operator sets it: credentials given so trstctl could verify a
	// challenge are not consent to publish into the zone on a public CA's
	// behalf, and as validation windows compress that publishing becomes
	// frequent and unattended.
	AllowUpstreamDV bool `json:"allow_upstream_dv,omitempty"`
}

type dns01ProviderConfigResponse struct {
	ID               string          `json:"id"`
	TenantID         string          `json:"tenant_id"`
	Name             string          `json:"name"`
	Provider         string          `json:"provider"`
	Zone             string          `json:"zone,omitempty"`
	ChallengeDomain  string          `json:"challenge_domain,omitempty"`
	DelegationTarget string          `json:"delegation_target,omitempty"`
	CredentialRefs   json.RawMessage `json:"credential_refs"`
	Config           json.RawMessage `json:"config"`
	CAAIssuerDomain  string          `json:"caa_issuer_domain,omitempty"`
	AllowedMethods   []string        `json:"allowed_methods"`
	AllowWildcards   bool            `json:"allow_wildcards"`
	AllowUpstreamDV  bool            `json:"allow_upstream_dv"`
	SecretHandling   string          `json:"secret_handling"`
	CreatedAt        string          `json:"created_at"`
	UpdatedAt        string          `json:"updated_at"`
}

type dns01ProviderConfigListResponse struct {
	Items []dns01ProviderConfigResponse `json:"items"`
}

type dns01PreflightRequest struct {
	ConfigID        string   `json:"config_id"`
	Domain          string   `json:"domain"`
	MethodOverride  string   `json:"method_override,omitempty"`
	ExpectedTXT     string   `json:"expected_txt,omitempty"`
	ObservedTXT     []string `json:"observed_txt,omitempty"`
	ObservedCNAME   string   `json:"observed_cname,omitempty"`
	Port80Reachable bool     `json:"port80_reachable,omitempty"`
}

type dns01PreflightCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// dns01CAAPolicyRecord is one public DNS policy record observed during the live
// preflight. It deliberately contains no resolver packet metadata or provider
// credential material.
type dns01CAAPolicyRecord struct {
	Flag uint8  `json:"flag"`
	Tag  string `json:"tag"`
	Data string `json:"value"`
}

// dns01CAAPolicyEvidence turns the binary CAA gate into an operator workflow:
// what live DNS said, why issuance is allowed or blocked, and the shortest safe
// recovery. CAA records are public DNS policy and may be returned unredacted.
type dns01CAAPolicyEvidence struct {
	Status             string                 `json:"status"`
	Source             string                 `json:"source"`
	ConfiguredIssuer   string                 `json:"configured_issuer,omitempty"`
	GoverningName      string                 `json:"governing_name,omitempty"`
	Wildcard           bool                   `json:"wildcard"`
	RelevantTag        string                 `json:"relevant_tag"`
	Records            []dns01CAAPolicyRecord `json:"records"`
	AllowedIssuers     []string               `json:"allowed_issuers"`
	RecommendedRecords []string               `json:"recommended_records"`
	RecoverySteps      []string               `json:"recovery_steps"`
	FailClosed         bool                   `json:"fail_closed"`
}

type dns01PreflightResponse struct {
	Ready           bool                   `json:"ready"`
	ConfigID        string                 `json:"config_id"`
	Domain          string                 `json:"domain"`
	RecordName      string                 `json:"record_name"`
	SelectedMethod  string                 `json:"selected_method"`
	MethodRationale string                 `json:"method_rationale"`
	Wildcard        bool                   `json:"wildcard"`
	Checks          []dns01PreflightCheck  `json:"checks"`
	FailedChecks    []string               `json:"failed_checks"`
	CAAPolicy       dns01CAAPolicyEvidence `json:"caa_policy"`
}

var servedDNS01ProviderCatalog = []ACMEDNS01ProviderCatalogItem{
	{
		Name: "route53", DisplayName: "AWS Route 53", Kind: "hosted-dns",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		AdmissionState: "built-in", Provenance: "core-build",
		CredentialReferenceFields: []string{"hosted_zone_id", "aws_access_key_ref", "aws_secret_key_ref", "aws_session_token_ref"},
		Capabilities:              []string{"net.dial:route53.amazonaws.com"},
		ProviderPackage:           "internal/dns/route53",
		Notes:                     "UPSERT/DELETE TXT records through Route 53; request signing stays behind internal/crypto.",
	},
	{
		Name: "googledns", DisplayName: "Google Cloud DNS", Kind: "hosted-dns",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		AdmissionState: "built-in", Provenance: "core-build",
		CredentialReferenceFields: []string{"project", "managed_zone", "oauth_token_ref"},
		Capabilities:              []string{"net.dial:dns.googleapis.com"},
		ProviderPackage:           "internal/dns/googledns",
		Notes:                     "Posts Cloud DNS Change resources with add/delete rrsets.",
	},
	{
		Name: "azuredns", DisplayName: "Azure DNS", Kind: "hosted-dns",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		AdmissionState: "built-in", Provenance: "core-build",
		CredentialReferenceFields: []string{"subscription_id", "resource_group", "zone", "aad_token_ref"},
		Capabilities:              []string{"net.dial:management.azure.com"},
		ProviderPackage:           "internal/dns/azuredns",
		Notes:                     "Uses Azure DNS record-set PUT/DELETE with a scoped bearer token.",
	},
	{
		Name: "cloudflare", DisplayName: "Cloudflare DNS", Kind: "hosted-dns",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		AdmissionState: "built-in", Provenance: "core-build",
		CredentialReferenceFields: []string{"zone_id", "api_token_ref"},
		Capabilities:              []string{"net.dial:api.cloudflare.com"},
		ProviderPackage:           "internal/dns/cloudflare",
		Notes:                     "Lists, creates, and deletes TXT records through Cloudflare's DNS Records API.",
	},
	{
		Name: "rfc2136", DisplayName: "RFC 2136 dynamic DNS", Kind: "dynamic-dns",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		AdmissionState: "built-in", Provenance: "core-build",
		CredentialReferenceFields: []string{"server", "zone", "tsig_key_name", "tsig_secret_ref"},
		Capabilities:              []string{"net.dial:authoritative-dns-server"},
		ProviderPackage:           "internal/dns/rfc2136",
		Notes:                     "Sends DNS UPDATE add/delete messages with TSIG material held as secret bytes.",
	},
	{
		Name: "webhook", DisplayName: "Generic DNS webhook", Kind: "webhook",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		AdmissionState: "built-in", Provenance: "core-build",
		CredentialReferenceFields: []string{"endpoint", "bearer_token_ref"},
		Capabilities:              []string{"net.dial:webhook-host"},
		ProviderPackage:           "internal/dns/webhook",
		Notes:                     "Calls operator-owned present/cleanup endpoints for providers outside the built-in catalog.",
	},
	{
		Name: "ns1", DisplayName: "NS1", Kind: "hosted-dns",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		AdmissionState: "built-in", Provenance: "core-build",
		CredentialReferenceFields: []string{"zone", "api_key_ref"},
		Capabilities:              []string{"net.dial:api.nsone.net"},
		ProviderPackage:           "internal/dns/ns1",
		Notes:                     "Built-in provider beyond the CAP-ISS-02 denominator.",
	},
	{
		Name: "akamai", DisplayName: "Akamai Edge DNS", Kind: "hosted-dns",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		AdmissionState: "built-in", Provenance: "core-build",
		CredentialReferenceFields: []string{"contract_id", "group_id", "zone", "client_token_ref", "client_secret_ref", "access_token_ref"},
		Capabilities:              []string{"net.dial:akamai-edgedns-host"},
		ProviderPackage:           "internal/dns/akamai",
		Notes:                     "Built-in provider beyond the CAP-ISS-02 denominator.",
	},
	{
		Name: "ultradns", DisplayName: "UltraDNS", Kind: "hosted-dns",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		AdmissionState: "built-in", Provenance: "core-build",
		CredentialReferenceFields: []string{"zone", "bearer_token_ref"},
		Capabilities:              []string{"net.dial:api.ultradns.com"},
		ProviderPackage:           "internal/dns/ultradns",
		Notes:                     "Built-in provider beyond the CAP-ISS-02 denominator.",
	},
	{
		Name: "acmedns", DisplayName: "acme-dns", Kind: "delegated-validation-dns",
		Served: true, PropagationPreflight: true, Conformance: "present-validate-cleanup",
		AdmissionState: "built-in", Provenance: "core-build",
		CredentialReferenceFields: []string{"subdomain", "username_ref", "password_ref"},
		Capabilities:              []string{"net.dial:auth.acme-dns.io"},
		ProviderPackage:           "internal/dns/acmedns",
		Notes:                     "Delegated validation-zone provider for keeping production DNS untouched.",
	},
}

func (a *API) listACMEDNS01Providers(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.tenant(r); !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	a.writeJSON(w, http.StatusOK, dns01ProviderCatalogResponse{Items: a.dns01ProviderCatalog()})
}

//trstctl:mutation
func (a *API) createACMEDNS01ProviderConfig(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		req, err := a.decodeACMEDNS01ProviderConfigRequest(r)
		if err != nil {
			return 0, nil, err
		}
		id := googleuuid.NewString()
		if err := a.emitACMEDNS01ProviderConfig(ctx, tenantID, id, req); err != nil {
			return 0, nil, err
		}
		rec, err := a.store.GetACMEDNS01ProviderConfig(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, toDNS01ProviderConfigResponse(rec), nil
	})
}

func (a *API) listACMEDNS01ProviderConfigs(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "ACME DNS-01 provider configuration is not configured"))
		return
	}
	recs, err := a.store.ListACMEDNS01ProviderConfigs(r.Context(), tenantID)
	if err != nil {
		a.writeACMEDNS01Error(w, err)
		return
	}
	items := make([]dns01ProviderConfigResponse, 0, len(recs))
	for _, rec := range recs {
		items = append(items, toDNS01ProviderConfigResponse(rec))
	}
	a.writeJSON(w, http.StatusOK, dns01ProviderConfigListResponse{Items: items})
}

func (a *API) getACMEDNS01ProviderConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	rec, err := a.store.GetACMEDNS01ProviderConfig(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeACMEDNS01Error(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toDNS01ProviderConfigResponse(rec))
}

//trstctl:mutation
func (a *API) updateACMEDNS01ProviderConfig(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if _, err := a.store.GetACMEDNS01ProviderConfig(ctx, tenantID, id); err != nil {
			return 0, nil, err
		}
		req, err := a.decodeACMEDNS01ProviderConfigRequest(r)
		if err != nil {
			return 0, nil, err
		}
		if err := a.emitACMEDNS01ProviderConfig(ctx, tenantID, id, req); err != nil {
			return 0, nil, err
		}
		rec, err := a.store.GetACMEDNS01ProviderConfig(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, toDNS01ProviderConfigResponse(rec), nil
	})
}

//trstctl:mutation
func (a *API) deleteACMEDNS01ProviderConfig(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	id := r.PathValue("id")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if _, err := a.store.GetACMEDNS01ProviderConfig(ctx, tenantID, id); err != nil {
			return 0, nil, err
		}
		payload, err := json.Marshal(projections.ACMEDNS01ProviderConfigDeleted{ID: id})
		if err != nil {
			return 0, nil, err
		}
		if err := a.appendAndProjectACMEDNS01(ctx, tenantID, projections.EventACMEDNS01ProviderConfigDeleted, payload); err != nil {
			return 0, nil, err
		}
		return http.StatusNoContent, nil, nil
	})
}

//trstctl:mutation
func (a *API) preflightACMEDNS01(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		var req dns01PreflightRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.ConfigID = strings.TrimSpace(req.ConfigID)
		req.Domain = strings.TrimSpace(req.Domain)
		req.MethodOverride = strings.TrimSpace(req.MethodOverride)
		req.ExpectedTXT = strings.TrimSpace(req.ExpectedTXT)
		req.ObservedCNAME = strings.TrimSpace(req.ObservedCNAME)
		if req.ConfigID == "" || req.Domain == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "config_id and domain are required")
		}
		cfg, err := a.store.GetACMEDNS01ProviderConfig(ctx, tenantID, req.ConfigID)
		if err != nil {
			return 0, nil, err
		}
		res := a.evaluateDNS01Preflight(ctx, req, cfg)
		payload, err := json.Marshal(projections.ACMEDNS01Preflighted{
			ConfigID: req.ConfigID, Domain: res.Domain, RecordName: res.RecordName,
			SelectedMethod: res.SelectedMethod, Ready: res.Ready, FailedChecks: res.FailedChecks,
		})
		if err != nil {
			return 0, nil, err
		}
		if err := a.appendAndProjectACMEDNS01(ctx, tenantID, projections.EventACMEDNS01Preflighted, payload); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, res, nil
	})
}

func (a *API) emitACMEDNS01ProviderConfig(ctx context.Context, tenantID, id string, req dns01ProviderConfigRequest) error {
	payload, err := json.Marshal(projections.ACMEDNS01ProviderConfigUpserted{
		ID: id, Name: req.Name, Provider: req.Provider, Zone: req.Zone,
		ChallengeDomain: req.ChallengeDomain, DelegationTarget: req.DelegationTarget,
		CredentialRefs: req.CredentialRefs, Config: req.Config, CAAIssuerDomain: req.CAAIssuerDomain,
		AllowedMethods: req.AllowedMethods, AllowWildcards: req.AllowWildcards,
		AllowUpstreamDV: req.AllowUpstreamDV,
	})
	if err != nil {
		return err
	}
	if a.store == nil {
		return errStatus(http.StatusServiceUnavailable, "ACME DNS-01 provider configuration is not configured")
	}
	// A tenant/name conflict is a command rejection, not a valid event. Hold the
	// deployment-wide projection lock across validation, append, and inline
	// projection so two replicas cannot both observe the name as free and append
	// a deterministic read-model failure that poisons the event tail.
	err = a.store.WithProjectionLock(ctx, func(lockCtx context.Context) error {
		if err := a.store.EnsureACMEDNS01ProviderConfigNameAvailable(lockCtx, tenantID, id, req.Name); err != nil {
			return err
		}
		return a.appendAndProjectACMEDNS01(lockCtx, tenantID, projections.EventACMEDNS01ProviderConfigUpserted, payload)
	})
	if errors.Is(err, store.ErrACMEDNS01ProviderConfigNameConflict) {
		return errStatus(http.StatusConflict, "ACME DNS-01 provider config name is already in use")
	}
	return err
}

func (a *API) appendAndProjectACMEDNS01(ctx context.Context, tenantID, eventType string, payload []byte) error {
	if a.store == nil || a.log == nil {
		return errStatus(http.StatusServiceUnavailable, "ACME DNS-01 provider configuration is not configured")
	}
	ev, err := a.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: payload})
	if err != nil {
		return err
	}
	return projections.New(a.store).Apply(ctx, ev)
}

func (a *API) decodeACMEDNS01ProviderConfigRequest(r *http.Request) (dns01ProviderConfigRequest, error) {
	var raw json.RawMessage
	if err := decodeJSON(r, &raw); err != nil {
		return dns01ProviderConfigRequest{}, errWithStatus(http.StatusBadRequest, err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return dns01ProviderConfigRequest{}, errStatus(http.StatusBadRequest, "request body must be a JSON object")
	}
	if containsInlineSecret(obj) {
		return dns01ProviderConfigRequest{}, errStatus(http.StatusBadRequest, "DNS-01 provider configs accept credential references, not inline secret values")
	}
	var req dns01ProviderConfigRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return dns01ProviderConfigRequest{}, errStatus(http.StatusBadRequest, "invalid DNS-01 provider config request")
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Provider = strings.TrimSpace(req.Provider)
	req.Zone = strings.TrimSpace(req.Zone)
	req.ChallengeDomain = strings.TrimSpace(req.ChallengeDomain)
	req.DelegationTarget = strings.TrimSpace(req.DelegationTarget)
	req.CAAIssuerDomain = strings.TrimSpace(req.CAAIssuerDomain)
	if req.Name == "" || req.Provider == "" {
		return dns01ProviderConfigRequest{}, errStatus(http.StatusBadRequest, "name and provider are required")
	}
	if !a.servedDNS01ProviderName(req.Provider) {
		return dns01ProviderConfigRequest{}, errStatus(http.StatusBadRequest, "provider must name a served DNS-01 provider")
	}
	refs, err := normalizeDNS01JSONObject(req.CredentialRefs, "credential_refs")
	if err != nil {
		return dns01ProviderConfigRequest{}, err
	}
	if err := validateCredentialRefObject(refs); err != nil {
		return dns01ProviderConfigRequest{}, err
	}
	cfg, err := normalizeDNS01JSONObject(req.Config, "config")
	if err != nil {
		return dns01ProviderConfigRequest{}, err
	}
	methods, err := normalizeDNS01Methods(req.AllowedMethods)
	if err != nil {
		return dns01ProviderConfigRequest{}, err
	}
	req.CredentialRefs = refs
	req.Config = cfg
	req.AllowedMethods = methods
	return req, nil
}

func normalizeDNS01JSONObject(raw json.RawMessage, field string) (json.RawMessage, error) {
	if len(raw) == 0 {
		return json.RawMessage(`{}`), nil
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, errStatus(http.StatusBadRequest, field+" must be a JSON object")
	}
	if containsInlineSecret(obj) {
		return nil, errStatus(http.StatusBadRequest, "DNS-01 provider configs accept credential references, not inline secret values")
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(out), nil
}

func validateCredentialRefObject(raw json.RawMessage) error {
	var refs map[string]string
	if err := json.Unmarshal(raw, &refs); err != nil {
		return errStatus(http.StatusBadRequest, "credential_refs values must be strings")
	}
	for key, value := range refs {
		k := strings.ToLower(strings.TrimSpace(key))
		if !strings.Contains(k, "ref") {
			return errStatus(http.StatusBadRequest, "credential_refs keys must be secret reference fields")
		}
		if strings.TrimSpace(value) == "" {
			return errStatus(http.StatusBadRequest, "credential_refs values must be non-empty references")
		}
	}
	return nil
}

func normalizeDNS01Methods(in []string) ([]string, error) {
	if len(in) == 0 {
		return []string{acmesrv.ChallengeDNS01}, nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, m := range in {
		m = strings.TrimSpace(m)
		switch m {
		case acmesrv.ChallengeHTTP01, acmesrv.ChallengeDNS01, acmesrv.ChallengeTLSALPN01:
			if !seen[m] {
				out = append(out, m)
				seen[m] = true
			}
		default:
			return nil, errStatus(http.StatusBadRequest, "allowed_methods must contain only http-01, dns-01, or tls-alpn-01")
		}
	}
	return out, nil
}

func (a *API) servedDNS01ProviderName(name string) bool {
	for _, item := range a.dns01ProviderCatalog() {
		if item.Name == name && item.Served {
			return true
		}
	}
	return false
}

func (a *API) dns01ProviderCatalog() []ACMEDNS01ProviderCatalogItem {
	out := make([]ACMEDNS01ProviderCatalogItem, 0, len(servedDNS01ProviderCatalog)+len(a.acmeDNS01Providers))
	out = append(out, servedDNS01ProviderCatalog...)
	out = append(out, a.acmeDNS01Providers...)
	return out
}

func toDNS01ProviderConfigResponse(rec store.ACMEDNS01ProviderConfig) dns01ProviderConfigResponse {
	refs := rec.CredentialRefs
	if len(refs) == 0 {
		refs = json.RawMessage(`{}`)
	}
	cfg := rec.Config
	if len(cfg) == 0 {
		cfg = json.RawMessage(`{}`)
	}
	methods := rec.AllowedMethods
	if methods == nil {
		methods = []string{}
	}
	return dns01ProviderConfigResponse{ // #nosec G101 -- identifier/constant matching the secret-name heuristic; no credential value present (CWE-798)
		ID: rec.ID, TenantID: rec.TenantID, Name: rec.Name, Provider: rec.Provider,
		Zone: rec.Zone, ChallengeDomain: rec.ChallengeDomain, DelegationTarget: rec.DelegationTarget,
		CredentialRefs: refs, Config: cfg, CAAIssuerDomain: rec.CAAIssuerDomain,
		AllowedMethods: methods, AllowWildcards: rec.AllowWildcards,
		AllowUpstreamDV: rec.AllowUpstreamDV,
		SecretHandling:  "credential_refs_only",
		CreatedAt:       rec.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:       rec.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
}

func (a *API) evaluateDNS01Preflight(ctx context.Context, req dns01PreflightRequest, cfg store.ACMEDNS01ProviderConfig) dns01PreflightResponse {
	domain := strings.TrimSpace(req.Domain)
	recordName := acmesrv.DNS01RecordName(domain)
	wildcard := acmesrv.IsWildcard(domain)
	method, rationale, methodErr := acmesrv.SelectMethod(acmesrv.MethodContext{
		Domain: domain, Wildcard: wildcard, Port80Reachable: req.Port80Reachable,
		DNSManaged: true, Override: req.MethodOverride,
	})
	checks := []dns01PreflightCheck{{Name: "provider_config", Status: "pass", Detail: "provider config is tenant-scoped and uses credential references"}}
	if methodErr != nil {
		checks = append(checks, dns01PreflightCheck{Name: "method_policy", Status: "fail", Detail: methodErr.Error()})
	} else if !stringIn(method, cfg.AllowedMethods) {
		checks = append(checks, dns01PreflightCheck{Name: "method_policy", Status: "fail", Detail: "selected method is not allowed by the DNS-01 provider policy"})
	} else {
		checks = append(checks, dns01PreflightCheck{Name: "method_policy", Status: "pass", Detail: rationale})
	}
	if methodErr == nil {
		if err := (acmesrv.WildcardPolicy{AllowWildcards: cfg.AllowWildcards}).CheckWildcard(domain, method); err != nil {
			checks = append(checks, dns01PreflightCheck{Name: "wildcard_policy", Status: "fail", Detail: err.Error()})
		} else {
			checks = append(checks, dns01PreflightCheck{Name: "wildcard_policy", Status: "pass", Detail: "wildcard policy allows this identifier/method pair"})
		}
	}
	checks = append(checks, delegationCheck(recordName, cfg.DelegationTarget, req.ObservedCNAME))
	checks = append(checks, propagationCheck(req.ExpectedTXT, req.ObservedTXT))
	caa, caaPolicy := caaPolicyCheck(ctx, a.acmeCAAResolver, domain, wildcard, cfg.CAAIssuerDomain)
	checks = append(checks, caa)

	failed := failedDNS01Checks(checks)
	return dns01PreflightResponse{
		Ready: len(failed) == 0, ConfigID: cfg.ID, Domain: domain, RecordName: recordName,
		SelectedMethod: method, MethodRationale: rationale, Wildcard: wildcard,
		Checks: checks, FailedChecks: failed, CAAPolicy: caaPolicy,
	}
}

func delegationCheck(recordName, wantTarget, got string) dns01PreflightCheck {
	wantTarget = strings.TrimSuffix(strings.TrimSpace(wantTarget), ".")
	got = strings.TrimSuffix(strings.TrimSpace(got), ".")
	if wantTarget == "" {
		return dns01PreflightCheck{Name: "cname_delegation", Status: "skipped", Detail: "provider config does not require CNAME delegation"}
	}
	if strings.EqualFold(got, wantTarget) {
		return dns01PreflightCheck{Name: "cname_delegation", Status: "pass", Detail: recordName + " is delegated to the configured validation target"}
	}
	return dns01PreflightCheck{Name: "cname_delegation", Status: "fail", Detail: recordName + " is not delegated to the configured validation target"}
}

func propagationCheck(expected string, observed []string) dns01PreflightCheck {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return dns01PreflightCheck{Name: "txt_propagation", Status: "skipped", Detail: "expected_txt was not supplied"}
	}
	for _, txt := range observed {
		if strings.TrimSpace(txt) == expected {
			return dns01PreflightCheck{Name: "txt_propagation", Status: "pass", Detail: "observed TXT contains the expected DNS-01 value"}
		}
	}
	return dns01PreflightCheck{Name: "txt_propagation", Status: "fail", Detail: "observed TXT records do not contain the expected DNS-01 value"}
}

func caaPolicyCheck(ctx context.Context, resolver acmesrv.CAAResolver, domain string, wildcard bool, issuer string) (dns01PreflightCheck, dns01CAAPolicyEvidence) {
	issuer = strings.TrimSpace(issuer)
	evidence := dns01CAAPolicyEvidence{
		Status: "not_configured", Source: "authoritative_live_dns", ConfiguredIssuer: issuer,
		Wildcard: wildcard, RelevantTag: "issue", Records: []dns01CAAPolicyRecord{},
		AllowedIssuers: []string{}, RecommendedRecords: []string{}, RecoverySteps: []string{},
		FailClosed: true,
	}
	if wildcard {
		evidence.RelevantTag = "issuewild"
	}
	if issuer == "" {
		evidence.RecoverySteps = []string{
			"Set the provider config's CAA issuer domain to the CA identifier expected in public DNS.",
			"Run this preflight again before relying on CAA enforcement.",
		}
		return dns01PreflightCheck{Name: "caa_policy", Status: "skipped", Detail: "provider config does not declare a CAA issuer domain"}, evidence
	}
	if resolver == nil {
		evidence.Status = "lookup_failed"
		evidence.RecoverySteps = caaLookupRecovery()
		return dns01PreflightCheck{Name: "caa_policy", Status: "fail", Detail: "CAA lookup failed closed: no live CAA resolver is configured"}, evidence
	}
	checker := acmesrv.CAAChecker{Resolver: resolver, IssuerDomain: issuer}
	inspection, err := checker.Inspect(ctx, domain, wildcard)
	evidence.GoverningName = inspection.GoverningName
	evidence.RelevantTag = inspection.RelevantTag
	evidence.AllowedIssuers = append(evidence.AllowedIssuers, inspection.AllowedIssuers...)
	for _, record := range inspection.Records {
		evidence.Records = append(evidence.Records, dns01CAAPolicyRecord{Flag: record.Flag, Tag: record.Tag, Data: record.Value})
	}
	if err != nil {
		if len(inspection.Records) == 0 {
			evidence.Status = "lookup_failed"
			evidence.RecoverySteps = caaLookupRecovery()
			return dns01PreflightCheck{Name: "caa_policy", Status: "fail", Detail: "live CAA lookup failed closed: " + err.Error()}, evidence
		}
		evidence.Status = "denied"
		evidence.RecommendedRecords = []string{recommendedCAARecord(inspection.GoverningName, inspection.RelevantTag, issuer)}
		evidence.RecoverySteps = []string{
			"Confirm that this issuer should be authorized for the requested name.",
			"Publish the recommended CAA record without removing other issuers your organization still uses.",
			"Wait for authoritative DNS to serve the new record, then run this preflight again.",
		}
		return dns01PreflightCheck{Name: "caa_policy", Status: "fail", Detail: "live governing CAA blocks the configured issuer: " + err.Error()}, evidence
	}
	if inspection.Unrestricted {
		evidence.Status = "unrestricted"
		name := strings.TrimSuffix(strings.TrimPrefix(domain, "*."), ".")
		evidence.RecommendedRecords = []string{recommendedCAARecord(name, evidence.RelevantTag, issuer)}
		evidence.RecoverySteps = []string{
			"Issuance is allowed because no CAA record currently limits which CA may issue.",
			"For tighter control, publish the recommended record and run this preflight again.",
		}
		return dns01PreflightCheck{Name: "caa_policy", Status: "pass", Detail: "no governing CAA record restricts issuance"}, evidence
	}
	evidence.Status = "allowed"
	evidence.RecoverySteps = []string{
		"No CAA change is required for this issuer and request type.",
		"Run this preflight again after any DNS or issuer configuration change.",
	}
	return dns01PreflightCheck{Name: "caa_policy", Status: "pass", Detail: "live governing CAA authorizes the configured issuer"}, evidence
}

func recommendedCAARecord(name, tag, issuer string) string {
	return strings.TrimSuffix(name, ".") + " CAA 0 " + tag + " \"" + issuer + "\""
}

func caaLookupRecovery() []string {
	return []string{
		"Repair authoritative DNS reachability, delegation, or the CAA response; trstctl will not guess while DNS is unavailable.",
		"Run this preflight again and require a live allowed or unrestricted result before issuance.",
	}
}

func failedDNS01Checks(checks []dns01PreflightCheck) []string {
	// failed_checks is a required array in the served OpenAPI contract. Start
	// non-nil so successful preflights encode as [] rather than JSON null; this
	// keeps generated clients and simple operator tooling type-safe.
	failed := make([]string, 0)
	for _, check := range checks {
		if check.Status == "fail" {
			failed = append(failed, check.Name)
		}
	}
	return failed
}

func stringIn(needle string, haystack []string) bool {
	for _, value := range haystack {
		if value == needle {
			return true
		}
	}
	return false
}

func (a *API) writeACMEDNS01Error(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrACMEDNS01ProviderConfigNotFound):
		a.writeError(w, errStatus(http.StatusNotFound, "ACME DNS-01 provider config not found"))
	case errors.Is(err, store.ErrACMEDNS01ProviderConfigNameConflict):
		a.writeError(w, errStatus(http.StatusConflict, "ACME DNS-01 provider config name is already in use"))
	default:
		a.writeError(w, err)
	}
}

// Upstream authorization staleness (epic B7).
//
// Automating DNS-01 upstream removes the human from the validation cycle, which
// also removes the human who used to NOTICE when validation stopped working. An
// authority that already holds a valid authorization issues without a
// challenge, so a broken publish path is invisible until the reuse window
// closes — and then it is not one certificate that fails, it is every
// identifier authorized in the same original burst, on the same day.
//
// This surface exists to make that visible early. The number it leads with is
// not "when does the certificate expire" but "when did this identifier last
// actually prove control", because those two diverge silently and the gap
// between them is the warning.

// ACMEUpstreamAuthorization is one identifier's authorization at one authority.
type ACMEUpstreamAuthorization struct {
	Identifier string `json:"identifier"`
	Issuer     string `json:"issuer"`
	// ChallengeType is empty when the last observation was a reuse. The
	// emptiness is information, not a missing field.
	ChallengeType string `json:"challenge_type,omitempty"`
	// LastValidatedAt is absent when trstctl has NEVER validated this
	// identifier at this authority — every issuance so far rode a reuse this
	// install did not earn and cannot repeat.
	LastValidatedAt string `json:"last_validated_at,omitempty"`
	LastReusedAt    string `json:"last_reused_at,omitempty"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	ReuseCount      int64  `json:"reuse_count"`
	ValidateCount   int64  `json:"validate_count"`
	// NeverValidated is the headline per row. It is derived rather than stored
	// so it cannot disagree with the timestamps beside it.
	NeverValidated bool `json:"never_validated"`
}

// ACMEUpstreamAuthorizationList is the served response.
type ACMEUpstreamAuthorizationList struct {
	Items []ACMEUpstreamAuthorization `json:"items"`
	// NeverValidatedCount is the number an operator should act on: identifiers
	// this install has issued for but never once validated itself.
	NeverValidatedCount int `json:"never_validated_count"`
	// Guidance travels with the data rather than living in documentation
	// nobody opens during an incident.
	Guidance string `json:"guidance"`
}

const acmeUpstreamAuthorizationGuidance = "An authority that already holds a valid authorization issues without a " +
	"challenge, so a broken validation path stays invisible while certificates keep arriving. Rows that have never " +
	"been validated by this install are the ones to act on: every issuance for them so far rode a reuse, and when " +
	"the authority's reuse window closes they fail together rather than one at a time. Empty is the honest answer " +
	"for a deployment that has not enabled upstream domain validation — it means nothing has been observed, not " +
	"that nothing is stale."

func (a *API) listACMEUpstreamAuthorizations(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "ACME DNS-01 provider configuration is not configured"))
		return
	}
	recs, err := a.store.ListACMEUpstreamAuthorizations(r.Context(), tenantID)
	if err != nil {
		a.writeACMEDNS01Error(w, err)
		return
	}
	out := ACMEUpstreamAuthorizationList{
		Items:    make([]ACMEUpstreamAuthorization, 0, len(recs)),
		Guidance: acmeUpstreamAuthorizationGuidance,
	}
	for _, rec := range recs {
		item := ACMEUpstreamAuthorization{
			Identifier: rec.Identifier, Issuer: rec.Issuer, ChallengeType: rec.ChallengeType,
			ReuseCount: rec.ReuseCount, ValidateCount: rec.ValidateCount,
			NeverValidated: rec.LastValidatedAt.IsZero(),
		}
		if !rec.LastValidatedAt.IsZero() {
			item.LastValidatedAt = rec.LastValidatedAt.UTC().Format(time.RFC3339)
		}
		if !rec.LastReusedAt.IsZero() {
			item.LastReusedAt = rec.LastReusedAt.UTC().Format(time.RFC3339)
		}
		if !rec.ExpiresAt.IsZero() {
			item.ExpiresAt = rec.ExpiresAt.UTC().Format(time.RFC3339)
		}
		if item.NeverValidated {
			out.NeverValidatedCount++
		}
		out.Items = append(out.Items, item)
	}
	a.writeJSON(w, http.StatusOK, out)
}
