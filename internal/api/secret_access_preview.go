// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
)

type secretAccessPreviewRequest struct {
	Name    string `json:"name"`
	EnvVar  string `json:"env_var"`
	Resolve bool   `json:"resolve"`
}

type secretAccessAPIRequest struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

type secretAccessBulkImport struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
	SafePath  string `json:"safe_path"`
}

type secretAccessPreviewResponse struct {
	Capability             string                 `json:"capability"`
	Operation              string                 `json:"operation"`
	Ready                  bool                   `json:"ready"`
	EffectFree             bool                   `json:"effect_free"`
	Name                   string                 `json:"name"`
	Version                int                    `json:"version,omitempty"`
	EnvVar                 string                 `json:"env_var"`
	ResolveReferences      bool                   `json:"resolve_references"`
	RequiredPermission     string                 `json:"required_permission"`
	RequestFingerprint     string                 `json:"request_fingerprint"`
	Blockers               []string               `json:"blockers"`
	PreviewReads           []string               `json:"preview_reads"`
	PreviewWrites          []string               `json:"preview_writes"`
	PreviewExternalEffects []string               `json:"preview_external_effects"`
	ExecuteReads           []string               `json:"execute_reads"`
	ExecuteDataFlow        []string               `json:"execute_data_flow"`
	RecoverySteps          []string               `json:"recovery_steps"`
	VerificationSteps      []string               `json:"verification_steps"`
	CLIArgv                []string               `json:"cli_argv"`
	APIRequest             secretAccessAPIRequest `json:"api_request"`
	TypeScript             string                 `json:"typescript"`
	BulkImport             secretAccessBulkImport `json:"bulk_import"`
	DataHandling           string                 `json:"secret_data_handling"`
}

func validSecretAccessEnvVar(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	for index := 0; index < len(name); index++ {
		char := name[index]
		valid := char == '_' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' || index > 0 && char >= '0' && char <= '9'
		if !valid || index == 0 && char >= '0' && char <= '9' {
			return false
		}
	}
	return true
}

func secretAccessStorePath(name string, resolve bool) string {
	parts := strings.Split(name, "/")
	for index := range parts {
		parts[index] = url.PathEscape(parts[index])
	}
	path := "/api/v1/secrets/store/" + strings.Join(parts, "/")
	if resolve {
		path += "?resolve=true"
	}
	return path
}

func secretAccessCLIArgv(req secretAccessPreviewRequest) []string {
	argv := []string{"trstctl", "run", "--secret", req.EnvVar + "=" + req.Name}
	if req.Resolve {
		argv = append(argv, "--resolve")
	}
	return append(argv, "--", "./service")
}

func secretAccessTypeScript(req secretAccessPreviewRequest) string {
	return "const secret = await client.secrets.get(" + strconv.Quote(req.Name) + ", { resolve: " + strconv.FormatBool(req.Resolve) + " });\n" +
		"process.env[" + strconv.Quote(req.EnvVar) + "] = secret.value; // memory only; never log or persist"
}

func (a *API) secretAccessPreviewFingerprint(tenantID, principal string, req secretAccessPreviewRequest, version int) (string, error) {
	if a.secrets == nil || a.secrets.be.CommandMAC == nil {
		return "", errors.New("api: server-keyed developer secret access preview evidence is unavailable")
	}
	material, err := json.Marshal(struct {
		Domain    string `json:"domain"`
		TenantID  string `json:"tenant_id"`
		Principal string `json:"principal"`
		Name      string `json:"name"`
		EnvVar    string `json:"env_var"`
		Resolve   bool   `json:"resolve"`
		Version   int    `json:"version"`
	}{
		Domain: "trstctl.api.developer-secret-access-preview.f64.v1", TenantID: tenantID,
		Principal: principal, Name: req.Name, EnvVar: req.EnvVar, Resolve: req.Resolve, Version: version,
	})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(material)
	mac, err := a.secrets.be.CommandMAC([]byte("trstctl.api.developer-secret-access-preview.f64.v1"), material)
	if err != nil {
		return "", err
	}
	if len(mac) != 32 {
		secret.Wipe(mac)
		return "", errors.New("api: developer secret access preview MAC has invalid length")
	}
	defer secret.Wipe(mac)
	return "sha256:" + hex.EncodeToString(mac), nil
}

func secretAccessPreviewBlocker(err error, direct bool) (string, bool) {
	var cycle secretReferenceCycleError
	var depth secretReferenceDepthError
	var statusErr *apiError
	switch {
	case errors.Is(err, store.ErrSecretNotFound) && direct:
		return "The named secret does not exist in this tenant.", true
	case errors.Is(err, store.ErrSecretNotFound):
		return "At least one referenced secret does not exist in this tenant.", true
	case errors.As(err, &cycle):
		return "Reference resolution found a cycle. Fix the references before running this access test.", true
	case errors.As(err, &depth):
		return "Reference resolution exceeded the safe depth limit. Shorten the reference chain before retrying.", true
	case errors.As(err, &statusErr) && statusErr.status >= 400 && statusErr.status < 500:
		return statusErr.detail, true
	default:
		return "", false
	}
}

// previewSecretAccess produces the exact, value-free developer plan for one
// authorized secret read. It transiently proves that the selected value can be
// opened (and, when requested, that its references can be resolved), then wipes the
// bytes. It appends no event or audit row and never returns secret material.
func (a *API) previewSecretAccess(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	var req secretAccessPreviewRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "name is required"))
		return
	}
	if len(req.Name) > 1024 {
		a.writeError(w, errStatus(http.StatusBadRequest, "name is too long"))
		return
	}
	if !validSecretAccessEnvVar(req.EnvVar) {
		a.writeError(w, errStatus(http.StatusBadRequest, "env_var must be a valid environment variable name"))
		return
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

	version := 0
	blockers := make([]string, 0, 1)
	rec, readErr := a.secrets.be.Store.GetSecret(r.Context(), tenantID, req.Name)
	if readErr == nil {
		version = rec.Version
		var value []byte
		if req.Resolve {
			value, version, readErr = a.resolveSecretValue(r.Context(), tenantID, req.Name, nil)
		} else {
			value, readErr = a.secrets.open(r.Context(), tenantID, rec.Sealed, sealAAD(tenantID, req.Name))
		}
		secret.Wipe(value)
	}
	if readErr != nil {
		if blocker, expected := secretAccessPreviewBlocker(readErr, version == 0); expected {
			blockers = append(blockers, blocker)
		} else {
			a.writeError(w, readErr)
			return
		}
	}
	fingerprint, err := a.secretAccessPreviewFingerprint(tenantID, principal, req, version)
	if err != nil {
		a.writeError(w, err)
		return
	}

	a.writeJSON(w, http.StatusOK, secretAccessPreviewResponse{
		Capability: "F64", Operation: "read_for_process", Ready: len(blockers) == 0, EffectFree: true,
		Name: req.Name, Version: version, EnvVar: req.EnvVar, ResolveReferences: req.Resolve,
		RequiredPermission: "secrets:read", RequestFingerprint: fingerprint, Blockers: blockers,
		PreviewReads: []string{
			"read one tenant-scoped secret metadata row",
			"open the selected value in transient memory and wipe it after validation",
		},
		PreviewWrites: []string{}, PreviewExternalEffects: []string{},
		ExecuteReads: []string{
			"GET the selected tenant-scoped secret through the served SDK path",
			"resolve ${secret.path} references only when explicitly enabled",
		},
		ExecuteDataFlow: []string{
			"return the value only to this authorized caller",
			"inject it into the child process environment without writing it to stdout, logs, browser storage, or a file",
		},
		RecoverySteps: []string{
			"Keep this reviewed plan and retry after restoring the secret, reference, permission, or tenant key domain.",
			"Review again if the secret version or any configured field changes.",
		},
		VerificationSteps: []string{
			"Confirm the access response name and version match this plan.",
			"Confirm the UI reports success without rendering or retaining the returned value.",
		},
		CLIArgv:    secretAccessCLIArgv(req),
		APIRequest: secretAccessAPIRequest{Method: http.MethodGet, Path: secretAccessStorePath(req.Name, req.Resolve)},
		TypeScript: secretAccessTypeScript(req),
		BulkImport: secretAccessBulkImport{
			Available: false,
			Reason:    "Atomic event-sourced bulk import is not implemented, so the compatibility route fails closed with 501 and the CLI exposes no import command.",
			SafePath:  "Create each secret with its own idempotency key, review the resulting metadata, then automate the same individual operation.",
		},
		DataHandling: "Preview opens the value only in transient wipeable server memory. The plan contains names, version, commands, and policy metadata only; it never returns, logs, persists, or sends the secret value.",
	})
}
