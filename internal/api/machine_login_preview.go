// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/secret"
)

const machineLoginPreviewDomain = "trstctl.api.machine-login-preview.f58.v1"

type machineLoginPreviewRequest struct {
	Method string `json:"method"`
}

type machineLoginPrerequisite struct {
	ID          string `json:"id"`
	Ready       bool   `json:"ready"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

type machineLoginPreviewResponse struct {
	Capability             string                     `json:"capability"`
	Operation              string                     `json:"operation"`
	Ready                  bool                       `json:"ready"`
	EffectFree             bool                       `json:"effect_free"`
	Method                 machineAuthMethodInfo      `json:"method"`
	TenantBinding          string                     `json:"tenant_binding"`
	CredentialFormat       string                     `json:"credential_format"`
	SessionTTLSeconds      int64                      `json:"session_ttl_seconds"`
	RequiredPermission     string                     `json:"required_permission"`
	RequestFingerprint     string                     `json:"request_fingerprint"`
	Prerequisites          []machineLoginPrerequisite `json:"prerequisites"`
	Blockers               []string                   `json:"blockers"`
	PreviewReads           []string                   `json:"preview_reads"`
	PreviewWrites          []string                   `json:"preview_writes"`
	PreviewExternalEffects []string                   `json:"preview_external_effects"`
	ExecuteWrites          []string                   `json:"execute_writes"`
	ExecuteExternalEffects []string                   `json:"execute_external_effects"`
	RecoverySteps          []string                   `json:"recovery_steps"`
	VerificationSteps      []string                   `json:"verification_steps"`
	CLIArgv                []string                   `json:"cli_argv"`
	DataHandling           string                     `json:"secret_data_handling"`
}

func (s *secretsService) machineSessionTTL() time.Duration {
	ttl := s.be.SessionTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	return ttl
}

// machineAuthMethodInventory is the one allow-listed projection used by the
// list and preview routes. Keeping one implementation prevents the review from
// describing a method that the login console cannot actually select.
func (a *API) machineAuthMethodInventory(ctx context.Context, tenantID string) ([]machineAuthMethodInfo, error) {
	disabled := map[string]bool{}
	if a.secrets.be.Store != nil {
		overlay, err := a.secrets.be.Store.DisabledMachineAuthMethods(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		disabled = overlay
	}
	items := make([]machineAuthMethodInfo, 0, 4)
	if len(a.secrets.be.AuthSecret) > 0 {
		items = append(items, machineAuthMethodInfo{
			Name: "token", Type: "token", Source: "builtin", Audience: "machine-login", Disabled: disabled["token"],
		})
	}
	if a.secrets.be.MachineAuthMethods != nil {
		for _, method := range a.secrets.be.MachineAuthMethods(tenantID) {
			if method == nil {
				continue
			}
			info := machineAuthMethodProjection(method, "config")
			info.Disabled = disabled[info.Name]
			items = append(items, info)
		}
	}
	return items, nil
}

func machineLoginTenantBinding(method machineAuthMethodInfo) string {
	if method.Type == "token" {
		return "The token MAC covers this tenant and the machine-login audience; another tenant or audience is rejected."
	}
	if method.TenantClaim != "" {
		return "The verified credential claim " + method.TenantClaim + " must name this tenant."
	}
	return "Server configuration pins this method to this tenant; the request header is only a lookup hint."
}

func machineLoginCredentialFormat(method machineAuthMethodInfo) string {
	switch method.Type {
	case "token":
		return "A tenant-, audience-, and expiry-bound trstctl machine token."
	case "kubernetes":
		return "A projected Kubernetes ServiceAccount JWT for an allowed namespace and service account."
	case "aws-iam":
		return "A Vault-style signed STS GetCallerIdentity request; never an AWS secret access key."
	case "gcp":
		return "A signed Google workload identity token for an allowed project and audience."
	case "azure":
		return "A signed Microsoft Entra workload token for an allowed tenant and audience."
	case "oidc", "jwt":
		return "A signed JWT whose issuer, audience, expiry, claims, and tenant binding match this method."
	default:
		return "The credential format declared by this configured machine-auth method."
	}
}

func machineLoginVerificationReady(method machineAuthMethodInfo) (bool, string, string) {
	switch method.Type {
	case "oidc", "jwt", "kubernetes", "gcp", "azure":
		return method.JWKSConfigured, "Public verification keys are loaded for this JWT-family method.", "Configure a trusted JWKS and restart or reload the control plane, then preview again."
	case "aws-iam":
		ready := len(method.AllowedAccounts) > 0 || len(method.AllowedARNs) > 0
		return ready, "AWS STS verification has an explicit account or ARN allowlist.", "Configure at least one allowed AWS account or ARN, then preview again."
	default:
		return true, "The method's local verification authority is configured.", "Restore the method verification authority, then preview again."
	}
}

func (a *API) machineLoginPreviewFingerprint(tenantID string, method machineAuthMethodInfo, ttl time.Duration) (string, error) {
	if a.secrets == nil || a.secrets.be.CommandMAC == nil {
		return "", errors.New("api: server-keyed machine-login preview evidence is unavailable")
	}
	material, err := json.Marshal(struct {
		Domain    string                `json:"domain"`
		TenantID  string                `json:"tenant_id"`
		Operation string                `json:"operation"`
		Method    machineAuthMethodInfo `json:"method"`
		TTL       int64                 `json:"session_ttl_seconds"`
	}{
		Domain: machineLoginPreviewDomain, TenantID: tenantID,
		Operation: "test_machine_login", Method: method, TTL: int64(ttl.Seconds()),
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(material)
	mac, err := a.secrets.be.CommandMAC([]byte(machineLoginPreviewDomain), material)
	if err != nil {
		return "", err
	}
	if len(mac) != 32 {
		secret.Wipe(mac)
		return "", errors.New("api: machine-login preview MAC has invalid length")
	}
	defer secret.Wipe(mac)
	return "sha256:" + hex.EncodeToString(mac), nil
}

// previewMachineLogin returns the exact secret-free operator plan for testing
// one configured method. It never accepts a credential, invokes a verifier,
// starts a session, appends an event, records idempotency state, or calls out.
func (a *API) previewMachineLogin(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	var req machineLoginPreviewRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	req.Method = strings.TrimSpace(req.Method)
	if req.Method == "" {
		req.Method = "token"
	}
	if len(req.Method) > 128 {
		a.writeError(w, errStatus(http.StatusBadRequest, "method name is too long"))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	methods, err := a.machineAuthMethodInventory(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	var selected *machineAuthMethodInfo
	for index := range methods {
		if methods[index].Name == req.Method {
			selected = &methods[index]
			break
		}
	}
	if selected == nil {
		a.writeError(w, errStatus(http.StatusNotFound, "no such configured machine-auth method"))
		return
	}
	ttl := a.secrets.machineSessionTTL()
	verificationReady, verificationDetail, verificationRemediation := machineLoginVerificationReady(*selected)
	methodEnabledDetail := "The selected method accepts new logins."
	if selected.Disabled {
		methodEnabledDetail = "The selected method is disabled for this tenant."
	}
	prerequisites := []machineLoginPrerequisite{
		{ID: "method_configured", Ready: true, Detail: "The selected method exists in this tenant's served configuration."},
		{ID: "method_enabled", Ready: !selected.Disabled, Detail: methodEnabledDetail, Remediation: "Re-enable this method for the tenant, then preview again."},
		{ID: "verification_authority", Ready: verificationReady, Detail: verificationDetail, Remediation: verificationRemediation},
		{ID: "session_ledger", Ready: a.machineSessionLedgerReady(), Detail: "Successful logins are appended and projected into the tenant-scoped issued-session ledger.", Remediation: "Restore PostgreSQL and the event log before testing a login."},
	}
	blockers := make([]string, 0, len(prerequisites))
	for _, prerequisite := range prerequisites {
		if !prerequisite.Ready {
			blockers = append(blockers, prerequisite.Detail+" "+prerequisite.Remediation)
		}
	}
	fingerprint, err := a.machineLoginPreviewFingerprint(tenantID, *selected, ttl)
	if err != nil {
		a.writeError(w, err)
		return
	}
	externalEffects := []string{}
	if selected.Type == "aws-iam" {
		externalEffects = append(externalEffects, "send the signed caller-identity request to the configured AWS STS verifier")
	}
	a.writeJSON(w, http.StatusOK, machineLoginPreviewResponse{
		Capability: "F58", Operation: "test_machine_login", Ready: len(blockers) == 0, EffectFree: true,
		Method: *selected, TenantBinding: machineLoginTenantBinding(*selected), CredentialFormat: machineLoginCredentialFormat(*selected),
		SessionTTLSeconds: int64(ttl.Seconds()), RequiredPermission: "secrets:read", RequestFingerprint: fingerprint,
		Prerequisites: prerequisites, Blockers: blockers,
		PreviewReads:  []string{"read the tenant-scoped method projection and disable overlay"},
		PreviewWrites: []string{}, PreviewExternalEffects: []string{},
		ExecuteWrites: []string{
			"append one plaintext-free auth.session.issued audit event",
			"append and project one tenant-scoped secrets.session.started ledger event",
		},
		ExecuteExternalEffects: externalEffects,
		RecoverySteps: []string{
			"Do not retry a rejected credential blindly; correct its tenant, audience, expiry, signature, allowlist, or method selection first.",
			"If this method is disabled, re-enable it deliberately and obtain a fresh preview before testing again.",
			"Revoke a successful synthetic test session from the issued-session ledger when verification is complete.",
		},
		VerificationSteps: []string{
			"Confirm the response method, principal, scopes, and expiry match the reviewed method and session lifetime.",
			"Confirm the new session ID appears in the tenant-scoped Issued sessions ledger, then revoke the synthetic session.",
		},
		CLIArgv:      []string{"trstctl", "secrets", "login", "-f", "machine-login.json"},
		DataHandling: "Preview never receives a credential. Execution consumes credential bytes once, never echoes or logs them, and the console clears its password field after every attempt.",
	})
}
