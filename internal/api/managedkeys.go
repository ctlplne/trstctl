// SPDX-License-Identifier: BUSL-1.1

package api

// Served BYOK/HSM managed-key lifecycle (CRYPTO-005 / EXC-CRYPTO-01). The
// crypto.RemoteKeyLifecycle primitives (generate/rotate/revoke/zeroize for a key
// whose private material lives in a KMS/HSM and never enters this process) were
// previously library-tier — implemented and tested but reachable from no served
// route. These handlers expose them on the running control plane: each is
// tenant-scoped (AN-1), idempotent (AN-5) through a.mutate, event-sourced (AN-2) via
// the managedkeys.Service's injected sink, and — for the destructive transitions —
// gated by the same distinct-approver dual control the served issuance gate uses.
// The private key is never in a request or response; for a remote key it is never
// in this address space at all.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/managedkeystate"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// ManagedKey is the key-material-free result contract returned by the licensed
// managed-key implementation. Core API owns this DTO so the route handlers do not
// link the EE service package.
type ManagedKey struct {
	// Provider is the provider holding the key (A199: several may run at once).
	Provider         string           `json:"provider,omitempty"`
	KeyID            string           `json:"key_id"`
	Algorithm        crypto.Algorithm `json:"algorithm"`
	Version          int              `json:"version"`
	State            string           `json:"state"`
	PublicDER        []byte           `json:"public_der,omitempty"`
	Extractable      bool             `json:"extractable"`
	CustodyStatus    string           `json:"custody_status,omitempty"`
	CustodyCheckedAt *time.Time       `json:"custody_checked_at,omitempty"`
}

// ManagedKeyCustodyVerifier is attached by the durable licensed service. A
// fresh proof is a provider signature over a signer-generated challenge.
// An empty provider resolves the key's provider from its handle.
type ManagedKeyCustodyVerifier interface {
	VerifyCustody(ctx context.Context, tenantID, provider, keyID, requester, idempotencyKey, requestBinding string) (ManagedKey, error)
}

// ManagedKeyOperationPendingError means the requested event and its outbox
// effect were committed, while the provider worker has not reached a terminal
// result within the synchronous wait. Retrying the mutation is unnecessary;
// callers can read the tenant-scoped operation instead.
type ManagedKeyOperationPendingError struct{ OperationID string }

func (e *ManagedKeyOperationPendingError) Error() string {
	return "managedkeys: durable operation is pending"
}

type managedKeyOperationResponse struct {
	OperationID string     `json:"operation_id"`
	Status      string     `json:"status"`
	StatusURL   string     `json:"status_url"`
	Provider    string     `json:"provider,omitempty"`
	Action      string     `json:"action,omitempty"`
	KeyID       string     `json:"key_id,omitempty"`
	ResultKeyID string     `json:"result_key_id,omitempty"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty"`
}

func validManagedKeyOperationID(id string) bool {
	const prefix = "managedkey:"
	if !strings.HasPrefix(id, prefix) || len(id) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(id[len(prefix):])
	return err == nil
}

func managedKeyPendingResponse(err error) (managedKeyOperationResponse, bool) {
	var pending *ManagedKeyOperationPendingError
	if !errors.As(err, &pending) || !validManagedKeyOperationID(pending.OperationID) {
		return managedKeyOperationResponse{}, false
	}
	return managedKeyOperationResponse{
		OperationID: pending.OperationID, Status: "queued",
		StatusURL: "/api/v1/managed-keys/operations/" + pending.OperationID,
	}, true
}

var (
	ErrManagedKeyNotApproved = errors.New("managedkeys: dual-control approval required")
	ErrManagedKeyUnknown     = errors.New("managedkeys: unknown key for tenant")
	ErrManagedKeyRefRequired = errors.New("managedkeys: key ref (id) is required")
	// ErrManagedKeyProviderNotAllowed means the deployment does not run the
	// provider, or the tenant's keys are pinned to another one (A199).
	ErrManagedKeyProviderNotAllowed = errors.New("managedkeys: provider is not available to this tenant")
	// ErrManagedKeyAmbiguous means a key handle exists under two providers and
	// the request did not name which.
	ErrManagedKeyAmbiguous = errors.New("managedkeys: key handle exists under several providers")
)

// ManagedKeyApprovalPendingError carries the exact immutable approval request
// opened by a destructive managed-key command. A caller may show this as a
// waiting state; other approval refusals remain failures.
type ManagedKeyApprovalPendingError struct {
	RequestID    string
	IntentDigest string
	Reason       string
}

func (e *ManagedKeyApprovalPendingError) Error() string {
	return ErrManagedKeyNotApproved.Error() + ": " + e.Reason
}

func (e *ManagedKeyApprovalPendingError) Unwrap() error { return ErrManagedKeyNotApproved }

// ManagedKeyService is the served managed-key lifecycle the API drives.
// The API depends only on this minimal interface
// so it never links a concrete KMS backend; the composition root wires the backend,
// event sink, dual-control gate, and optional service-level idempotency into the
// service. The served HTTP path binds every handler's canonical command and
// authenticated principal before invoking the durable service (AN-5). The same raw
// Idempotency-Key reaches both layers so the API owns byte-for-byte HTTP replay and
// the durable receiver owns collapse of the event/outbox effect.
// Generate names the provider the key is created under; the actions take the
// key's provider, or empty to resolve it from the key handle.
type ManagedKeyService interface {
	Generate(ctx context.Context, tenantID, provider string, alg crypto.Algorithm, idempotencyKey, requestBinding string) (ManagedKey, error)
	Rotate(ctx context.Context, tenantID, provider, keyID, requester, idempotencyKey, requestBinding string) (ManagedKey, error)
	Revoke(ctx context.Context, tenantID, provider, keyID, requester, idempotencyKey, requestBinding string) (ManagedKey, error)
	Zeroize(ctx context.Context, tenantID, provider, keyID, requester, idempotencyKey, requestBinding string) (ManagedKey, error)
}

// ManagedKeyCustodyConfiguration is the intentionally tiny, secret-free part of
// startup configuration the operator workflow may observe. Provider credentials,
// token values, module PINs, auth values, and filesystem paths never cross this
// seam. The full configuration remains owned by the composition root and isolated
// signer (AN-4/AN-8).
type ManagedKeyCustodyConfiguration struct {
	Enabled bool
	// Provider is the deployment's default provider; Providers every provider
	// it runs (A199); TenantProviders the tenants pinned to one of them.
	Provider        string
	Providers       []string
	TenantProviders map[string]string
}

// ManagedKeyCustodyRequirement describes one deployment prerequisite without its
// value. Secret inputs are always described as file references; the API and browser
// never accept or return their contents.
type ManagedKeyCustodyRequirement struct {
	Key                 string `json:"key"`
	Label               string `json:"label"`
	Kind                string `json:"kind"`
	Required            bool   `json:"required"`
	EnvironmentVariable string `json:"environment_variable"`
	Description         string `json:"description"`
}

// ManagedKeyCustodyProvider is one shipped custody adapter and its structured,
// secret-free deployment contract.
type ManagedKeyCustodyProvider struct {
	ID           string                         `json:"id"`
	Label        string                         `json:"label"`
	Custody      string                         `json:"custody"`
	Requirements []ManagedKeyCustodyRequirement `json:"requirements"`
}

// ManagedKeyCustodyPlan reports what this exact process has attached and how to
// configure each shipped provider. It is a plan/readiness surface, not a runtime
// configuration mutation: changing custody requires a reviewed deployment restart.
type ManagedKeyCustodyPlan struct {
	Enabled            bool   `json:"enabled"`
	LifecycleAttached  bool   `json:"lifecycle_attached"`
	Ready              bool   `json:"ready"`
	ConfiguredProvider string `json:"configured_provider"`
	// ConfiguredProviders lists every provider the deployment runs; a key may
	// be generated under any of them unless TenantProvider pins the caller's
	// tenant to one.
	ConfiguredProviders []string                    `json:"configured_providers"`
	TenantProvider      string                      `json:"tenant_provider,omitempty"`
	ConfigurationMode   string                      `json:"configuration_mode"`
	SecretDelivery      string                      `json:"secret_delivery"`
	RestartRequired     bool                        `json:"restart_required"`
	SecurityBoundary    string                      `json:"security_boundary"`
	Providers           []ManagedKeyCustodyProvider `json:"providers"`
	Blockers            []string                    `json:"blockers"`
}

// ManagedKeyGenerationPreview is the exact effect-free review returned before a
// key generation request. Preview never calls the provider, appends an event, or
// enqueues outbox work; it names the effects the later execution will perform.
type ManagedKeyGenerationPreview struct {
	Ready                    bool                           `json:"ready"`
	EffectFree               bool                           `json:"effect_free"`
	Provider                 string                         `json:"provider"`
	ProviderLabel            string                         `json:"provider_label"`
	Algorithm                string                         `json:"algorithm"`
	ConfigurationMode        string                         `json:"configuration_mode"`
	RestartRequired          bool                           `json:"restart_required"`
	Extractable              bool                           `json:"extractable"`
	PrivateKeyLocation       string                         `json:"private_key_location"`
	RequiredPermission       string                         `json:"required_permission"`
	ApprovalRequired         bool                           `json:"approval_required"`
	Requirements             []ManagedKeyCustodyRequirement `json:"requirements"`
	PreviewWrites            []string                       `json:"preview_writes"`
	PreviewExternalEffects   []string                       `json:"preview_external_effects"`
	ExecutionWrites          []string                       `json:"execution_writes"`
	ExecutionExternalEffects []string                       `json:"execution_external_effects"`
	Proof                    []string                       `json:"proof"`
	Blockers                 []string                       `json:"blockers"`
}

type managedKeyGenerationPreviewRequest struct {
	Provider  string `json:"provider"`
	Algorithm string `json:"algorithm"`
}

// WithManagedKeys mounts the served managed-key lifecycle surface (CRYPTO-005). When
// unset, the /api/v1/managed-keys/* routes fail closed with a clear "not enabled"
// problem (the capability requires a configured KMS/HSM custody backend).
func WithManagedKeys(svc ManagedKeyService) Option {
	return func(c *config) { c.managedKeys = svc }
}

// WithManagedKeyCustody publishes only the enabled/provider posture needed by the
// planning UI. Provider credentials and paths deliberately remain outside the API.
func WithManagedKeyCustody(posture ManagedKeyCustodyConfiguration) Option {
	return func(c *config) {
		posture.Provider = normalizeManagedKeyProvider(posture.Provider)
		providers := make([]string, 0, len(posture.Providers))
		for _, provider := range posture.Providers {
			if provider = normalizeManagedKeyProvider(provider); provider != "" && !slices.Contains(providers, provider) {
				providers = append(providers, provider)
			}
		}
		if posture.Enabled && posture.Provider == "" {
			posture.Provider = "aws"
			if len(providers) > 0 {
				posture.Provider = providers[0]
			}
		}
		if posture.Enabled && len(providers) == 0 {
			providers = []string{posture.Provider}
		}
		pins := make(map[string]string, len(posture.TenantProviders))
		for tenantID, provider := range posture.TenantProviders {
			pins[tenantID] = normalizeManagedKeyProvider(provider)
		}
		posture.Providers, posture.TenantProviders = providers, pins
		if !posture.Enabled {
			posture.Provider, posture.Providers, posture.TenantProviders = "", nil, nil
		}
		c.managedKeyCustody = posture
	}
}

// ManagedKeysServed reports whether the served managed-key surface is wired
// (WithManagedKeys was given). It is the CRYPTO-005 wiring assertion the acceptance
// test consults.
func (a *API) ManagedKeysServed() bool { return a.managedKeys != nil }

func managedKeysDisabledProblem() *apiError {
	return errStatus(http.StatusNotImplemented,
		"managed-key lifecycle is not enabled (configure a KMS/HSM custody backend)")
}

const (
	managedKeyConfigurationMode = "startup_static"
	managedKeySecretDelivery    = "file_reference_only"
)

func managedKeyCustodyProviders() []ManagedKeyCustodyProvider {
	value := func(key, label, env, description string, required bool) ManagedKeyCustodyRequirement {
		return ManagedKeyCustodyRequirement{Key: key, Label: label, Kind: "value", Required: required, EnvironmentVariable: env, Description: description}
	}
	secretFile := func(key, label, env, description string, required bool) ManagedKeyCustodyRequirement {
		return ManagedKeyCustodyRequirement{Key: key, Label: label, Kind: "secret_file", Required: required, EnvironmentVariable: env, Description: description}
	}
	return []ManagedKeyCustodyProvider{
		{ID: "aws", Label: "AWS KMS", Custody: "AWS creates and retains the asymmetric private key inside KMS.", Requirements: []ManagedKeyCustodyRequirement{
			value("region", "AWS region", "TRSTCTL_MANAGED_KEYS_AWS_REGION", "Region containing the KMS key.", true),
			value("access_key_id", "Access key ID", "TRSTCTL_MANAGED_KEYS_AWS_ACCESS_KEY_ID", "Identifier for the narrowly scoped KMS principal.", true),
			secretFile("secret_access_key_file", "Secret access key file", "TRSTCTL_MANAGED_KEYS_AWS_SECRET_ACCESS_KEY_FILE", "Mode-0600 file read by the isolated signer at startup.", true),
			secretFile("session_token_file", "Session token file", "TRSTCTL_MANAGED_KEYS_AWS_SESSION_TOKEN_FILE", "Optional mode-0600 file for temporary AWS credentials.", false),
		}},
		{ID: "azure-key-vault", Label: "Azure Key Vault / Managed HSM", Custody: "Azure creates and retains the asymmetric private key inside the selected vault or Managed HSM.", Requirements: []ManagedKeyCustodyRequirement{
			value("vault_url", "Vault URL", "TRSTCTL_MANAGED_KEYS_AZURE_VAULT_URL", "HTTPS URL of the tenant-approved vault or Managed HSM.", true),
			secretFile("bearer_token_file", "Bearer token file", "TRSTCTL_MANAGED_KEYS_AZURE_BEARER_TOKEN_FILE", "Mode-0600 file containing a short-lived Azure access token.", true),
		}},
		{ID: "gcp-kms", Label: "Google Cloud KMS", Custody: "Google Cloud creates and retains the asymmetric private key inside Cloud KMS.", Requirements: []ManagedKeyCustodyRequirement{
			value("parent", "Key ring resource", "TRSTCTL_MANAGED_KEYS_GCP_PARENT", "Full projects/.../locations/.../keyRings/... parent resource.", true),
			secretFile("bearer_token_file", "Bearer token file", "TRSTCTL_MANAGED_KEYS_GCP_BEARER_TOKEN_FILE", "Mode-0600 file containing a short-lived Google Cloud access token.", true),
		}},
		{ID: "pkcs11", Label: "PKCS#11 HSM", Custody: "The HSM creates and retains the asymmetric private key in its token slot.", Requirements: []ManagedKeyCustodyRequirement{
			value("module_path", "PKCS#11 module", "TRSTCTL_MANAGED_KEYS_PKCS11_MODULE_PATH", "Native module path available only to the cgo signer artifact.", true),
			value("token_label", "Token label", "TRSTCTL_MANAGED_KEYS_PKCS11_TOKEN_LABEL", "Initialized HSM token selected by the signer.", true),
			secretFile("user_pin_file", "User PIN file", "TRSTCTL_MANAGED_KEYS_PKCS11_USER_PIN_FILE", "Mode-0600 file used only by the isolated signer.", true),
		}},
		{ID: "tpm2", Label: "TPM 2.0", Custody: "The TPM creates and retains the asymmetric private key behind a persistent device handle.", Requirements: []ManagedKeyCustodyRequirement{
			value("path", "TPM device or socket", "TRSTCTL_MANAGED_KEYS_TPM2_PATH", "Linux TPM resource-manager device or approved swtpm Unix socket.", true),
			secretFile("owner_auth_file", "Owner authorization file", "TRSTCTL_MANAGED_KEYS_TPM2_OWNER_AUTH_FILE", "Optional mode-0600 TPM owner authorization file.", false),
			secretFile("key_auth_file", "Key authorization file", "TRSTCTL_MANAGED_KEYS_TPM2_KEY_AUTH_FILE", "Optional mode-0600 authorization file for created keys.", false),
		}},
		{ID: "yubihsm2", Label: "YubiHSM 2", Custody: "YubiHSM creates and retains the asymmetric private key behind its PKCS#11 connector.", Requirements: []ManagedKeyCustodyRequirement{
			value("module_path", "YubiHSM PKCS#11 module", "TRSTCTL_MANAGED_KEYS_YUBIHSM2_MODULE_PATH", "Path to Yubico's yubihsm_pkcs11 module in the cgo signer artifact.", true),
			value("token_label", "Connector token label", "TRSTCTL_MANAGED_KEYS_YUBIHSM2_TOKEN_LABEL", "Approved YubiHSM connector/token label.", true),
			secretFile("user_pin_file", "Authentication file", "TRSTCTL_MANAGED_KEYS_YUBIHSM2_USER_PIN_FILE", "Mode-0600 authentication file used only by the isolated signer.", true),
		}},
	}
}

func normalizeManagedKeyProvider(provider string) string {
	return strings.ToLower(strings.TrimSpace(provider))
}

// managedKeyCustodyID is the custody ID of a provider name as the inventory
// reports it; only AWS differs ("aws-kms" is "aws").
func managedKeyCustodyID(provider string) string {
	if provider = normalizeManagedKeyProvider(provider); provider == "aws-kms" {
		return "aws"
	}
	return provider
}

func managedKeyProvider(provider string) (ManagedKeyCustodyProvider, bool) {
	provider = normalizeManagedKeyProvider(provider)
	for _, candidate := range managedKeyCustodyProviders() {
		if candidate.ID == provider {
			return candidate, true
		}
	}
	return ManagedKeyCustodyProvider{}, false
}

// managedKeyProviderBlocker says why a provider cannot take this tenant's new
// key, or "" when it can: the deployment runs it, and the tenant is not pinned
// to another provider.
func (a *API) managedKeyProviderBlocker(tenantID, provider string) string {
	if !slices.Contains(a.managedKeyCustody.Providers, provider) {
		return "This deployment does not run " + provider + "; it runs " + strings.Join(a.managedKeyCustody.Providers, ", ") +
			". Add the provider to the startup configuration and restart before generating a key under it."
	}
	if pinned, ok := a.managedKeyCustody.TenantProviders[tenantID]; ok && pinned != provider {
		return "This tenant's managed keys are pinned to " + pinned + "."
	}
	return ""
}

func (a *API) managedKeyCustodyPlan(tenantID string) ManagedKeyCustodyPlan {
	blockers := make([]string, 0, 2)
	if !a.managedKeyCustody.Enabled {
		blockers = append(blockers, "Managed-key custody is disabled. Enable it, select a provider, supply file-backed credentials where required, and restart the control plane and isolated signer.")
	}
	if a.managedKeys == nil {
		blockers = append(blockers, "The managed-key runtime is not attached. Verify the Enterprise BYOK license and provider configuration, then restart the deployment.")
	}
	ready := len(blockers) == 0
	return ManagedKeyCustodyPlan{
		Enabled: a.managedKeyCustody.Enabled, LifecycleAttached: a.managedKeys != nil, Ready: ready,
		ConfiguredProvider: a.managedKeyCustody.Provider, ConfigurationMode: managedKeyConfigurationMode,
		ConfiguredProviders: append([]string{}, a.managedKeyCustody.Providers...),
		TenantProvider:      a.managedKeyCustody.TenantProviders[tenantID],
		SecretDelivery:      managedKeySecretDelivery, RestartRequired: !ready,
		SecurityBoundary: "Private keys stay in the selected provider. Provider credentials are startup file references consumed by the isolated signer; the browser never receives their values.",
		Providers:        managedKeyCustodyProviders(), Blockers: blockers,
	}
}

func (a *API) getManagedKeyCustody(w http.ResponseWriter, r *http.Request) {
	tenantID, _ := a.tenant(r)
	a.writeJSON(w, http.StatusOK, a.managedKeyCustodyPlan(tenantID))
}

func (a *API) previewManagedKeyGeneration(w http.ResponseWriter, r *http.Request) {
	var req managedKeyGenerationPreviewRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	provider, ok := managedKeyProvider(req.Provider)
	if !ok {
		a.writeError(w, errStatus(http.StatusBadRequest, `provider must be "aws", "azure-key-vault", "gcp-kms", "pkcs11", "tpm2", or "yubihsm2"`))
		return
	}
	alg, err := parseManagedKeyAlgorithm(req.Algorithm)
	if err != nil {
		a.writeError(w, err)
		return
	}
	blockers := make([]string, 0, 2)
	tenantID, _ := a.tenant(r)
	if !a.managedKeyCustody.Enabled {
		blockers = append(blockers, "Managed-key custody is disabled. Apply the selected provider's startup configuration and restart the control plane and isolated signer.")
	} else if blocker := a.managedKeyProviderBlocker(tenantID, provider.ID); blocker != "" {
		blockers = append(blockers, blocker)
	}
	if a.managedKeys == nil {
		blockers = append(blockers, "The managed-key runtime is not attached. Verify the Enterprise BYOK license and provider configuration, then restart the deployment.")
	}
	ready := len(blockers) == 0
	a.writeJSON(w, http.StatusOK, ManagedKeyGenerationPreview{
		Ready: ready, EffectFree: true, Provider: provider.ID, ProviderLabel: provider.Label,
		Algorithm: string(alg), ConfigurationMode: managedKeyConfigurationMode, RestartRequired: !ready,
		Extractable: false, PrivateKeyLocation: provider.Label,
		RequiredPermission: string(authz.KeysWrite), ApprovalRequired: false,
		Requirements: provider.Requirements, PreviewWrites: []string{}, PreviewExternalEffects: []string{},
		ExecutionWrites:          []string{"One tenant-scoped byok.key.generated event and its managed-key projection."},
		ExecutionExternalEffects: []string{"One durable managedkey.command outbox intent to the isolated signer and selected custody provider."},
		Proof:                    []string{"Provider key handle", "public-key fingerprint", "non-extractable state", "immutable audit event"},
		Blockers:                 blockers,
	})
}

// ---- request/response shapes (key-material-free) ---------------------------

type managedKeyGenerateRequest struct {
	Provider  string `json:"provider"`
	Algorithm string `json:"algorithm"`
}

type managedKeyActionRequest struct {
	KeyID string `json:"key_id"`
	// Provider names the key's provider when its handle exists under more than
	// one; empty resolves it from the handle.
	Provider string `json:"provider,omitempty"`
}

type managedKeyApprovalRequest struct {
	KeyID        string `json:"key_id"`
	Action       string `json:"action"`
	RequestID    string `json:"request_id"`
	IntentDigest string `json:"intent_digest"`
}

type managedKeyApprovalResponse struct {
	Resource  string `json:"resource"`
	Action    string `json:"action"`
	Approver  string `json:"approver"`
	Approvals int    `json:"approvals"`
}

// Managed-key action constants are the canonical approval/service vocabulary.
// The core recorder and licensed lifecycle both compile against these values, so
// an approval can never drift onto a lookalike action string.
const (
	ManagedKeyActionGenerate      = "managedkey:generate"
	ManagedKeyActionRotate        = "managedkey:rotate"
	ManagedKeyActionRevoke        = "managedkey:revoke"
	ManagedKeyActionZeroize       = "managedkey:zeroize"
	ManagedKeyActionVerifyCustody = "managedkey:verify_custody"
)

var managedKeyApprovalActions = []string{"rotate", "revoke", "zeroize"}

var managedKeyCanonicalApprovalActions = []string{
	ManagedKeyActionRotate,
	ManagedKeyActionRevoke,
	ManagedKeyActionZeroize,
}

// managedKeyResponse is the public view of a managed key: identity, algorithm,
// version, state, and PKIX public key — never the private material.
type managedKeyResponse struct {
	Provider         string     `json:"provider"`
	KeyID            string     `json:"key_id"`
	Algorithm        string     `json:"algorithm"`
	Version          int        `json:"version"`
	State            string     `json:"state"`
	PublicDER        []byte     `json:"public_der,omitempty"`
	Extractable      bool       `json:"extractable"`
	CustodyStatus    string     `json:"custody_status,omitempty"`
	CustodyCheckedAt *time.Time `json:"custody_checked_at,omitempty"`
}

func toManagedKeyResponse(r ManagedKey, provider string) managedKeyResponse {
	if r.Provider != "" {
		provider = r.Provider
	}
	return managedKeyResponse{
		Provider:      provider,
		KeyID:         r.KeyID,
		Algorithm:     string(r.Algorithm),
		Version:       r.Version,
		State:         managedkeystate.PublicState(provider, r.State),
		PublicDER:     r.PublicDER,
		Extractable:   r.Extractable,
		CustodyStatus: r.CustodyStatus, CustodyCheckedAt: r.CustodyCheckedAt,
	}
}

// The inventory contains only the durable, event-projected public metadata.
// Provider is part of the identity: a key handle can occur in two backends.
type managedKeyRecordResponse struct {
	Provider         string     `json:"provider"`
	KeyID            string     `json:"key_id"`
	Algorithm        string     `json:"algorithm"`
	Version          int        `json:"version"`
	State            string     `json:"state"`
	PublicDER        []byte     `json:"public_der,omitempty"`
	Extractable      bool       `json:"extractable"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	CustodyStatus    string     `json:"custody_status"`
	CustodyCheckedAt *time.Time `json:"custody_checked_at,omitempty"`
}

type managedKeyRecordListResponse struct {
	Items      []managedKeyRecordResponse `json:"items"`
	NextCursor string                     `json:"next_cursor"`
}

func toManagedKeyRecordResponse(key store.ManagedKey) managedKeyRecordResponse {
	return managedKeyRecordResponse{
		Provider: key.Provider, KeyID: key.KeyID, Algorithm: key.Algorithm,
		Version: key.Version, State: managedkeystate.PublicState(key.Provider, key.State), PublicDER: key.PublicDER,
		Extractable: false, CreatedAt: key.CreatedAt, UpdatedAt: key.UpdatedAt,
		CustodyStatus: key.CustodyStatus, CustodyCheckedAt: key.CustodyCheckedAt,
	}
}

func managedKeyCursor(provider, keyID string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(provider + "\x00" + keyID))
}

func parseManagedKeyCursor(raw string) (string, string, error) {
	if raw == "" {
		return "", "", nil
	}
	if len(raw) > 1024 {
		return "", "", errors.New("invalid managed-key cursor")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return "", "", errors.New("invalid managed-key cursor")
	}
	provider, keyID, found := strings.Cut(string(decoded), "\x00")
	if !utf8.Valid(decoded) || !found || provider == "" || keyID == "" ||
		len(provider) > 128 || len(keyID) > 512 || strings.ContainsRune(keyID, '\x00') {
		return "", "", errors.New("invalid managed-key cursor")
	}
	return provider, keyID, nil
}

func (a *API) listManagedKeys(w http.ResponseWriter, r *http.Request) {
	if a.managedKeys == nil || a.store == nil {
		a.writeError(w, managedKeysDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, err := pageLimit(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	provider, keyID, err := parseManagedKeyCursor(r.URL.Query().Get("cursor"))
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	keys, err := a.store.ListManagedKeysPage(r.Context(), tenantID, provider, keyID, limit+1)
	if err != nil {
		a.writeError(w, err)
		return
	}
	next := ""
	if len(keys) > limit {
		keys = keys[:limit]
		last := keys[len(keys)-1]
		next = managedKeyCursor(last.Provider, last.KeyID)
	}
	items := make([]managedKeyRecordResponse, 0, len(keys))
	for _, key := range keys {
		items = append(items, toManagedKeyRecordResponse(key))
	}
	a.writeJSON(w, http.StatusOK, managedKeyRecordListResponse{Items: items, NextCursor: next})
}

func (a *API) getManagedKey(w http.ResponseWriter, r *http.Request) {
	if a.managedKeys == nil || a.store == nil {
		a.writeError(w, managedKeysDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	provider, keyID := r.PathValue("provider"), r.PathValue("key_id")
	if provider == "" || keyID == "" {
		a.writeError(w, errStatus(http.StatusNotFound, "no such managed key for this tenant"))
		return
	}
	key, err := a.store.GetManagedKey(r.Context(), tenantID, provider, keyID)
	if store.IsNotFound(err) {
		a.writeError(w, errStatus(http.StatusNotFound, "no such managed key for this tenant"))
		return
	}
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, toManagedKeyRecordResponse(key))
}

func (a *API) getManagedKeyOperation(w http.ResponseWriter, r *http.Request) {
	if a.managedKeys == nil || a.store == nil {
		a.writeError(w, managedKeysDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	id := r.PathValue("operation_id")
	if !validManagedKeyOperationID(id) {
		a.writeError(w, errStatus(http.StatusNotFound, "no such managed-key operation for this tenant"))
		return
	}
	op, err := a.store.GetManagedKeyOperation(r.Context(), tenantID, id)
	if store.IsNotFound(err) {
		a.writeError(w, errStatus(http.StatusNotFound, "no such managed-key operation for this tenant"))
		return
	}
	if err != nil {
		a.writeError(w, err)
		return
	}
	if op.Status != "queued" && op.Status != "completed" && op.Status != "failed" {
		a.writeError(w, errStatus(http.StatusInternalServerError, "managed-key operation has an unknown status"))
		return
	}
	a.writeJSON(w, http.StatusOK, managedKeyOperationResponse{
		OperationID: id, Status: op.Status,
		StatusURL: "/api/v1/managed-keys/operations/" + id,
		Provider:  op.Provider, Action: op.Action, KeyID: op.KeyID,
		ResultKeyID: op.ResultKeyID, UpdatedAt: &op.UpdatedAt,
	})
}

// requesterFor returns the authenticated principal's subject, which the dual-control
// gate treats as the requester (and therefore never counts as its own approver).
func requesterFor(ctx context.Context) (string, error) {
	p, _ := ctx.Value(principalCtxKey).(authz.Principal)
	if p.Subject == "" {
		return "", errStatus(http.StatusUnauthorized, "an authenticated principal is required")
	}
	return p.Subject, nil
}

// mapManagedKeyError maps service-layer errors to problem+json statuses.
func mapManagedKeyError(err error) error {
	var pending *ManagedKeyApprovalPendingError
	switch {
	case errors.Is(err, orchestrator.ErrIdempotencyConflict):
		return errStatus(http.StatusConflict, "Idempotency-Key was already used for a different authenticated request")
	case errors.As(err, &pending):
		return &apiError{status: http.StatusForbidden, detail: "dual control: " + err.Error(), ext: map[string]any{
			"code": "managed_key_approval_pending", "approval_request_id": pending.RequestID,
			"intent_digest": pending.IntentDigest,
		}}
	case errors.Is(err, ErrManagedKeyNotApproved):
		return errStatus(http.StatusForbidden, "dual control: "+err.Error())
	case errors.Is(err, ErrManagedKeyUnknown):
		return errStatus(http.StatusNotFound, "no such managed key for this tenant")
	case errors.Is(err, ErrManagedKeyRefRequired):
		return errStatus(http.StatusBadRequest, "key_id is required")
	case errors.Is(err, ErrManagedKeyProviderNotAllowed):
		return errStatus(http.StatusConflict, "this provider is not available to this tenant; review custody and preview again")
	case errors.Is(err, ErrManagedKeyAmbiguous):
		return errStatus(http.StatusConflict, "this key handle exists under more than one provider; name the provider")
	default:
		return err
	}
}

// ---- handlers --------------------------------------------------------------

// generateManagedKey mints a new managed key in the configured KMS/HSM. The private
// material is born in the provider and never enters this process. Idempotent (AN-5),
// event-sourced (AN-2). Generation creates new material, so it needs no prior
// approval.
//
//trstctl:mutation
func (a *API) generateManagedKey(w http.ResponseWriter, r *http.Request) {
	if a.managedKeys == nil {
		a.writeError(w, managedKeysDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req managedKeyGenerateRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if req.Algorithm == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "algorithm is required"))
		return
	}
	provider, ok := managedKeyProvider(req.Provider)
	if !ok {
		a.writeError(w, errStatus(http.StatusBadRequest, `provider must be "aws", "azure-key-vault", "gcp-kms", "pkcs11", "tpm2", or "yubihsm2"`))
		return
	}
	callerTenant, _ := a.tenant(r)
	if !a.managedKeyCustody.Enabled || a.managedKeys == nil || a.managedKeyProviderBlocker(callerTenant, provider.ID) != "" {
		a.writeError(w, errStatus(http.StatusConflict, "selected managed-key provider is not configured, attached and available to this tenant; review custody and preview again"))
		return
	}
	alg, err := parseManagedKeyAlgorithm(req.Algorithm)
	if err != nil {
		a.writeError(w, err)
		return
	}
	requester, err := requesterFor(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := managedKeyRequestBinding("generate", requester, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		res, err := a.managedKeys.Generate(ctx, tenantID, provider.ID, alg, idempotencyKey, binding)
		if err != nil {
			if pending, ok := managedKeyPendingResponse(err); ok {
				return http.StatusAccepted, pending, nil
			}
			return 0, nil, mapManagedKeyError(err)
		}
		return http.StatusCreated, toManagedKeyResponse(res, provider.ID), nil
	})
}

// rotateManagedKey mints a successor for an existing managed key (supersede-then-
// retire). Destructive of the current generation's authority, so it requires a
// distinct-approver approval (dual control) enforced by the service.
//
//trstctl:mutation
func (a *API) rotateManagedKey(w http.ResponseWriter, r *http.Request) {
	if a.managedKeys == nil {
		a.writeError(w, managedKeysDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.managedKeyAction(w, r, idempotencyKey, "rotate", a.managedKeys.Rotate)
}

// revokeManagedKey disables a managed key at the provider (it refuses further
// signatures). Requires a distinct-approver approval (dual control).
//
//trstctl:mutation
func (a *API) revokeManagedKey(w http.ResponseWriter, r *http.Request) {
	if a.managedKeys == nil {
		a.writeError(w, managedKeysDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.managedKeyAction(w, r, idempotencyKey, "revoke", a.managedKeys.Revoke)
}

// zeroizeManagedKey schedules destruction of a managed key's material at the
// provider (irreversible after the provider window). Requires a distinct-approver
// approval (dual control).
//
//trstctl:mutation
func (a *API) zeroizeManagedKey(w http.ResponseWriter, r *http.Request) {
	if a.managedKeys == nil {
		a.writeError(w, managedKeysDisabledProblem())
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.managedKeyAction(w, r, idempotencyKey, "zeroize", a.managedKeys.Zeroize)
}

// verifyManagedKeyCustody queues a signer-isolated challenge signature. It
// updates only the event-projected last proof; lifecycle state is untouched.
//
//trstctl:mutation
func (a *API) verifyManagedKeyCustody(w http.ResponseWriter, r *http.Request) {
	if a.managedKeys == nil {
		a.writeError(w, managedKeysDisabledProblem())
		return
	}
	verifier, ok := a.managedKeys.(ManagedKeyCustodyVerifier)
	if !ok {
		a.writeError(w, errStatus(http.StatusNotImplemented, "managed-key custody verification is not attached"))
		return
	}
	a.managedKeyAction(w, r, r.Header.Get("Idempotency-Key"), "verify_custody", verifier.VerifyCustody)
}

// approveManagedKeyAction records one distinct principal's approval for an exact
// opaque provider key handle and destructive action. The key id stays in JSON: HSM
// and cloud-KMS handles routinely contain slashes and must never be reinterpreted
// as URL path segments. Only this closed-set translation can produce the canonical
// managedkey:* action strings consulted by the licensed lifecycle service.
//
//trstctl:mutation
func (a *API) approveManagedKeyAction(w http.ResponseWriter, r *http.Request) {
	if a.managedKeys == nil {
		a.writeError(w, managedKeysDisabledProblem())
		return
	}
	if a.approvals == nil {
		a.writeError(w, errStatus(http.StatusNotImplemented, "managed-key dual-control approval is not enabled on this deployment"))
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req managedKeyApprovalRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if req.KeyID == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "key_id is required"))
		return
	}
	canonicalAction, ok := canonicalManagedKeyApprovalAction(req.Action)
	if !ok {
		a.writeError(w, errStatus(http.StatusBadRequest, `action must be "rotate", "revoke", or "zeroize"`))
		return
	}
	approver, err := requesterFor(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	command := ApprovalDecisionCommand{
		RequestID: strings.TrimSpace(req.RequestID), IntentDigest: strings.TrimSpace(req.IntentDigest),
		Approver: approver, Decision: store.ApprovalDecisionApprove,
		ExpectedResourceKind: "managed_key", ExpectedResourceID: req.KeyID,
		ExpectedAction: canonicalAction,
	}
	if _, err := a.preflightApprovalDecision(r, command); err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := managedKeyRequestBinding("approve:"+canonicalAction, approver, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateWithRecorder(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		record, recordErr := a.approvals.RecordApproval(ctx, tenantID, command)
		if recordErr != nil {
			return 0, nil, approvalAPIError(recordErr)
		}
		return http.StatusOK, managedKeyApprovalResponse{
			Resource: req.KeyID, Action: canonicalAction, Approver: approver, Approvals: record.ApprovalCount,
		}, nil
	}, false)
}

func canonicalManagedKeyApprovalAction(action string) (string, bool) {
	switch action {
	case "rotate":
		return ManagedKeyActionRotate, true
	case "revoke":
		return ManagedKeyActionRevoke, true
	case "zeroize":
		return ManagedKeyActionZeroize, true
	default:
		return "", false
	}
}

// managedKeyAction is the shared body of key-bound handlers. It decodes and
// validates the command and authenticated requester before the recorder can return
// a cached response, then binds both to the raw tenant-global idempotency key. A
// changed key, action, or caller therefore receives 409 without reaching approval
// or the durable service.
func (a *API) managedKeyAction(w http.ResponseWriter, r *http.Request, idempotencyKey, operation string, op func(ctx context.Context, tenantID, provider, keyID, requester, idem, requestBinding string) (ManagedKey, error)) {
	if idempotencyKey == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req managedKeyActionRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if req.KeyID == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "key_id is required"))
		return
	}
	req.Provider = normalizeManagedKeyProvider(req.Provider)
	if req.Provider != "" && !slices.Contains(a.managedKeyCustody.Providers, managedKeyCustodyID(req.Provider)) {
		a.writeError(w, errStatus(http.StatusBadRequest, "provider must be one of the providers this deployment runs"))
		return
	}
	requester, err := requesterFor(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := managedKeyRequestBinding(operation, requester, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		res, err := op(ctx, tenantID, req.Provider, req.KeyID, requester, idempotencyKey, binding)
		if err != nil {
			if pending, ok := managedKeyPendingResponse(err); ok {
				return http.StatusAccepted, pending, nil
			}
			return 0, nil, mapManagedKeyError(err)
		}
		// The result names its key's provider; a service that does not is
		// answered as the request's provider, else the deployment default.
		provider := req.Provider
		if provider == "" {
			provider = a.managedKeyCustody.Provider
		}
		return http.StatusOK, toManagedKeyResponse(res, provider), nil
	})
}

func parseManagedKeyAlgorithm(raw string) (crypto.Algorithm, error) {
	alg := crypto.Algorithm(raw)
	switch alg {
	case crypto.RSA2048, crypto.RSA3072, crypto.RSA4096,
		crypto.ECDSAP256, crypto.ECDSAP384, crypto.ECDSAP521:
		return alg, nil
	default:
		return "", errStatus(http.StatusBadRequest, "unsupported managed-key algorithm")
	}
}

func managedKeyRequestBinding(operation, principal string, request any) (string, error) {
	encoded, err := json.Marshal(struct {
		Domain    string `json:"domain"`
		Operation string `json:"operation"`
		Principal string `json:"principal"`
		Request   any    `json:"request"`
	}{Domain: "trstctl.api.managed-key-binding.v1", Operation: operation, Principal: principal, Request: request})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(encoded)
	return crypto.SHA256Hex(encoded), nil
}
