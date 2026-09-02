// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/pkisecret"
)

type pkiSecretPrerequisite struct {
	ID          string `json:"id"`
	Ready       bool   `json:"ready"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

type pkiSecretPreviewResponse struct {
	Capability             string                  `json:"capability"`
	Operation              string                  `json:"operation"`
	Ready                  bool                    `json:"ready"`
	EffectFree             bool                    `json:"effect_free"`
	CustodyMode            string                  `json:"custody_mode"`
	CommonName             string                  `json:"common_name"`
	DNSNames               []string                `json:"dns_names"`
	RequestedTTLSeconds    int                     `json:"requested_ttl_seconds"`
	EffectiveTTLSeconds    int64                   `json:"effective_ttl_seconds"`
	Profile                string                  `json:"profile"`
	CACertificateSHA256    string                  `json:"ca_certificate_sha256,omitempty"`
	CSRSHA256              string                  `json:"csr_sha256,omitempty"`
	SubjectKeyAlgorithm    string                  `json:"subject_key_algorithm"`
	SubjectKeyBits         int                     `json:"subject_key_bits"`
	RequiredPermission     string                  `json:"required_permission"`
	RequestFingerprint     string                  `json:"request_fingerprint"`
	VaultPath              string                  `json:"vault_path"`
	Prerequisites          []pkiSecretPrerequisite `json:"prerequisites"`
	Blockers               []string                `json:"blockers"`
	PreviewWrites          []string                `json:"preview_writes"`
	PreviewExternalEffects []string                `json:"preview_external_effects"`
	ExecuteWrites          []string                `json:"execute_writes"`
	ExecuteExternalEffects []string                `json:"execute_external_effects"`
	RecoverySteps          []string                `json:"recovery_steps"`
	VerificationSteps      []string                `json:"verification_steps"`
	CLIArgv                []string                `json:"cli_argv"`
	DataHandling           string                  `json:"secret_data_handling"`
}

func pkiSecretIssuancePlan(provider *pkisecret.PKIProvider, req pkiSecretRequest, csrDER []byte) (pkisecret.IssuancePlan, error) {
	if req.CSRPEM != "" {
		return provider.PlanFromCSRSeconds(csrDER, int64(req.TTLSeconds))
	}
	return provider.PlanGeneratedSeconds(req.CommonName, int64(req.TTLSeconds))
}

func pkiSecretCustodyMode(req pkiSecretRequest) string {
	if req.CSRPEM != "" {
		return "requester_csr"
	}
	return "deprecated_server_keygen"
}

func pkiSecretVaultPath(req pkiSecretRequest) string {
	if req.CSRPEM != "" {
		return "/v1/pki/sign/default"
	}
	return "/v1/pki/issue/default"
}

func (a *API) pkiSecretPreviewFingerprint(
	tenantID, principal string,
	req pkiSecretRequest,
	plan pkisecret.IssuancePlan,
	caCertDER, csrDER []byte,
) (string, error) {
	if a.secrets == nil || a.secrets.be.CommandMAC == nil {
		return "", errors.New("api: server-keyed PKI-secret preview evidence is unavailable")
	}
	material, err := json.Marshal(struct {
		Domain              string   `json:"domain"`
		TenantID            string   `json:"tenant_id"`
		Principal           string   `json:"principal"`
		Operation           string   `json:"operation"`
		CustodyMode         string   `json:"custody_mode"`
		CommonName          string   `json:"common_name"`
		DNSNames            []string `json:"dns_names"`
		RequestedTTLSeconds int      `json:"requested_ttl_seconds"`
		EffectiveTTLSeconds int64    `json:"effective_ttl_seconds"`
		Profile             string   `json:"profile"`
		CACertificateSHA256 string   `json:"ca_certificate_sha256"`
		CSRSHA256           string   `json:"csr_sha256,omitempty"`
		SubjectKeyAlgorithm string   `json:"subject_key_algorithm"`
		SubjectKeyBits      int      `json:"subject_key_bits"`
	}{
		Domain: "trstctl.api.pki-secret-preview.f67.v1", TenantID: tenantID, Principal: principal,
		Operation: "issue_certificate", CustodyMode: pkiSecretCustodyMode(req), CommonName: plan.CommonName,
		DNSNames:            plan.DNSNames,
		RequestedTTLSeconds: req.TTLSeconds, EffectiveTTLSeconds: int64(plan.EffectiveTTL.Seconds()), Profile: plan.Profile,
		CACertificateSHA256: crypto.SHA256Hex(caCertDER), CSRSHA256: crypto.SHA256Hex(csrDER),
		SubjectKeyAlgorithm: plan.KeyAlgorithm, SubjectKeyBits: plan.KeyBits,
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(material)
	mac, err := a.secrets.be.CommandMAC([]byte("trstctl.api.pki-secret-preview.f67.v1"), material)
	if err != nil {
		return "", err
	}
	if len(mac) != 32 {
		secret.Wipe(mac)
		return "", errors.New("api: PKI-secret preview MAC has invalid length")
	}
	defer secret.Wipe(mac)
	return "sha256:" + hex.EncodeToString(mac), nil
}

// previewPKISecret validates an exact PKI-secret request using the same provider
// rules as execution. It performs no signing, event append, projection write,
// audit, idempotency record, outbox enqueue, or external call.
func (a *API) previewPKISecret(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	var req pkiSecretRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	req.CommonName = strings.TrimSpace(req.CommonName)
	req.CSRPEM = strings.TrimSpace(req.CSRPEM)
	req.PreviewFingerprint = ""
	if req.TTLSeconds < 0 {
		a.writeError(w, errStatus(http.StatusBadRequest, "ttl_seconds cannot be negative"))
		return
	}
	if (req.CommonName == "") == (req.CSRPEM == "") {
		a.writeError(w, errStatus(http.StatusBadRequest, "exactly one of common_name or csr_pem is required"))
		return
	}
	var csrDER []byte
	if req.CSRPEM != "" {
		var err error
		csrDER, req.CommonName, err = decodePKISecretCSR([]byte(req.CSRPEM))
		if err != nil {
			a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
			return
		}
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	caCertDER, caSigner := a.secrets.resolveCA()
	provider := a.secrets.pkiProvider(tenantID, caCertDER, caSigner)
	plan, err := pkiSecretIssuancePlan(provider, req, csrDER)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}

	prerequisites := []pkiSecretPrerequisite{
		{ID: "secrets_api", Ready: true, Detail: "The tenant-scoped native secrets API is enabled."},
		{ID: "issuing_ca", Ready: caSigner != nil && len(caCertDER) > 0, Detail: "An issuing CA certificate and signer must be connected.", Remediation: "Configure or restore the issuing CA, then preview again."},
		{ID: "custody_input", Ready: true, Detail: "Exactly one custody mode is selected and its subject/key input passed profile validation."},
		{ID: "revocation_tracking", Ready: a.secrets.be.RevocationSink != nil, Detail: "Issued serials must be recorded on the tenant revocation pipeline.", Remediation: "Restore the revocation sink before issuing."},
	}
	if req.CSRPEM == "" {
		prerequisites = append(prerequisites, pkiSecretPrerequisite{
			ID: "durable_deprecation_evidence", Ready: a.secrets.be.Audit != nil,
			Detail:      "Legacy server-side key generation must record immutable deprecation evidence before creating a key.",
			Remediation: "Restore the audit/event sink or switch to requester CSR custody.",
		})
	}
	blockers := make([]string, 0, len(prerequisites))
	for _, prerequisite := range prerequisites {
		if !prerequisite.Ready {
			blockers = append(blockers, prerequisite.Detail+" "+prerequisite.Remediation)
		}
	}
	fingerprint, err := a.pkiSecretPreviewFingerprint(tenantID, principal, req, plan, caCertDER, csrDER)
	if err != nil {
		a.writeError(w, err)
		return
	}
	caDigest, csrDigest := "", ""
	if len(caCertDER) > 0 {
		caDigest = "sha256:" + crypto.SHA256Hex(caCertDER)
	}
	if len(csrDER) > 0 {
		csrDigest = "sha256:" + crypto.SHA256Hex(csrDER)
	}
	requestFile := "pki-request.json"
	a.writeJSON(w, http.StatusOK, pkiSecretPreviewResponse{
		Capability: "F67", Operation: "issue_certificate", Ready: len(blockers) == 0, EffectFree: true,
		CustodyMode: pkiSecretCustodyMode(req), CommonName: plan.CommonName, DNSNames: plan.DNSNames,
		RequestedTTLSeconds: req.TTLSeconds, EffectiveTTLSeconds: int64(plan.EffectiveTTL.Seconds()), Profile: plan.Profile,
		CACertificateSHA256: caDigest, CSRSHA256: csrDigest, SubjectKeyAlgorithm: plan.KeyAlgorithm, SubjectKeyBits: plan.KeyBits,
		RequiredPermission: "secrets:write", RequestFingerprint: fingerprint, VaultPath: pkiSecretVaultPath(req),
		Prerequisites: prerequisites, Blockers: blockers, PreviewWrites: []string{}, PreviewExternalEffects: []string{},
		ExecuteWrites: []string{
			"record the issued serial on the tenant revocation pipeline",
			"append plaintext-free pkisecret.issued audit evidence",
		},
		ExecuteExternalEffects: []string{"ask the configured issuing-CA signer to sign exactly one certificate"},
		RecoverySteps: []string{
			"Cancel before execution to leave the CA, event log, and certificate inventory unchanged.",
			"After execution, revoke the exact issued serial through the certificate revocation workflow.",
		},
		VerificationSteps: []string{
			"Verify the returned certificate common name, public key, issuer, and lifetime match this plan.",
			"Confirm the issued serial appears in tenant-scoped audit and revocation tracking.",
		},
		CLIArgv:      []string{"trstctl", "secrets", "pki", "-f", requestFile},
		DataHandling: "Preview parses only public CSR/subject data in transient memory. It never generates, receives, returns, logs, persists, signs with, or sends a subject private key; legacy execution returns a generated key once and is explicitly deprecated.",
	})
}
