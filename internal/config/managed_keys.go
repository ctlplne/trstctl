// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/netsec"
)

const (
	// ManagedKeyProviderAWS selects the AWS KMS custody backend for the served
	// managed-key lifecycle. The provider is chosen at startup through ordinary Go
	// interface injection (crypto.RemoteKeyLifecycle), not through a runtime crypto
	// engine/plugin registry; this is the same compile-time interface pattern as
	// crypto.Signer, Java JCA, OpenSSL ENGINE, and PKCS#11.
	ManagedKeyProviderAWS = "aws"
	// ManagedKeyProviderAzureKeyVault selects Azure Key Vault / Managed HSM for
	// served managed-key custody. The bearer token is supplied at startup and the
	// private key stays inside Azure.
	ManagedKeyProviderAzureKeyVault = "azure-key-vault"
	// ManagedKeyProviderGCPKMS selects Google Cloud KMS for served managed-key
	// custody. The bearer token is supplied at startup and the private key stays
	// inside Cloud KMS.
	ManagedKeyProviderGCPKMS = "gcp-kms"
	// ManagedKeyProviderPKCS11 selects a local PKCS#11 HSM module (SoftHSM,
	// nShield, Luna, or another standards-compliant token) for served managed-key
	// custody. The module is opened only by the managed-key backend package.
	ManagedKeyProviderPKCS11 = "pkcs11"
	// ManagedKeyProviderTPM2 selects a Linux TPM 2.0 device or swtpm Unix
	// socket. The production driver uses google/go-tpm in trstctl-signer.
	ManagedKeyProviderTPM2 = "tpm2"
	// ManagedKeyProviderYubiHSM2 selects Yubico's yubihsm_pkcs11 module, which
	// reaches the device through yubihsm-connector in the cgo signer artifact.
	ManagedKeyProviderYubiHSM2 = "yubihsm2"
)

// ManagedKeys configures the served BYOK/HSM managed-key lifecycle. Off by default:
// when disabled, /api/v1/managed-keys/* remains registered but fails closed with
// 501 until an operator supplies a custody backend.
type ManagedKeys struct {
	Enabled bool `json:"enabled,omitempty"`
	// Provider is the deployment's default provider: a key goes to it when
	// neither the request nor the tenant names another.
	Provider string `json:"provider,omitempty"`
	// Providers lists every provider the deployment runs at once (A199). Each
	// one's block below is validated and handed to the isolated signer, and a
	// key may be generated under any of them. Empty means Provider alone.
	Providers []string `json:"providers,omitempty"`
	// TenantProviders pins a tenant's managed keys to one listed provider; an
	// unpinned tenant chooses per key among the listed providers.
	TenantProviders []ManagedKeyTenantProvider `json:"tenant_providers,omitempty"`
	AWS             ManagedKeysAWSKMS          `json:"aws,omitempty"`
	Azure           ManagedKeysAzureKV         `json:"azure,omitempty"`
	GCP             ManagedKeysGCPKMS          `json:"gcp,omitempty"`
	PKCS11          ManagedKeysPKCS11HSM       `json:"pkcs11,omitempty"`
	TPM2            ManagedKeysTPM2            `json:"tpm2,omitempty"`
	YubiHSM2        ManagedKeysPKCS11HSM       `json:"yubihsm2,omitempty"`
}

// ManagedKeyTenantProvider pins one tenant's managed keys to one provider.
type ManagedKeyTenantProvider struct {
	TenantID string `json:"tenant_id"`
	Provider string `json:"provider"`
}

// normalizeManagedKeyProvider is a provider name as configuration compares it.
func normalizeManagedKeyProvider(provider string) string {
	return strings.ToLower(strings.TrimSpace(provider))
}

// EnabledProviders is every provider the deployment runs: Providers when set,
// else Provider alone (AWS KMS when that is empty too), normalized, in
// configured order, without duplicates.
func (m ManagedKeys) EnabledProviders() []string {
	var out []string
	for _, raw := range m.Providers {
		if provider := normalizeManagedKeyProvider(raw); provider != "" && !slices.Contains(out, provider) {
			out = append(out, provider)
		}
	}
	if len(out) == 0 {
		out = append(out, m.DefaultProvider())
	}
	return out
}

// DefaultProvider is the provider a key goes to when neither the request nor
// the tenant names one: Provider when set, else the first listed provider,
// else AWS KMS.
func (m ManagedKeys) DefaultProvider() string {
	if provider := normalizeManagedKeyProvider(m.Provider); provider != "" {
		return provider
	}
	for _, raw := range m.Providers {
		if provider := normalizeManagedKeyProvider(raw); provider != "" {
			return provider
		}
	}
	return ManagedKeyProviderAWS
}

// TenantProvider is the provider a tenant is pinned to, if any.
func (m ManagedKeys) TenantProvider(tenantID string) (string, bool) {
	for _, pin := range m.TenantProviders {
		if pin.TenantID == tenantID {
			return normalizeManagedKeyProvider(pin.Provider), true
		}
	}
	return "", false
}

// ManagedKeysAWSKMS configures AWS KMS custody for managed keys. Secret credential
// material is represented as []byte when supplied by the environment and may also
// be read from files, so startup can wipe temporary file buffers after constructing
// the backend. The private managed-key material itself never enters the process.
type ManagedKeysAWSKMS struct {
	Region                string   `json:"region,omitempty"`
	Endpoint              string   `json:"endpoint,omitempty"`
	AllowInsecureLoopback bool     `json:"allow_insecure_loopback,omitempty"`
	AccessKeyID           string   `json:"access_key_id,omitempty"`
	SecretAccessKey       []byte   `json:"secret_access_key,omitempty"`
	SecretAccessKeyFile   string   `json:"secret_access_key_file,omitempty"`
	SessionToken          []byte   `json:"session_token,omitempty"`
	SessionTokenFile      string   `json:"session_token_file,omitempty"`
	PrivateEgressCIDRs    []string `json:"private_egress_cidrs,omitempty"`
}

// ManagedKeysAzureKV configures Azure Key Vault / Managed HSM custody for managed
// keys. The bearer token is a short-lived AAD access token minted outside trstctl
// and kept as bytes until the HTTP authorization edge.
type ManagedKeysAzureKV struct {
	VaultURL              string   `json:"vault_url,omitempty"`
	Endpoint              string   `json:"endpoint,omitempty"`
	AllowInsecureLoopback bool     `json:"allow_insecure_loopback,omitempty"`
	BearerToken           []byte   `json:"bearer_token,omitempty"`
	BearerTokenFile       string   `json:"bearer_token_file,omitempty"`
	PrivateEgressCIDRs    []string `json:"private_egress_cidrs,omitempty"`
}

// ManagedKeysGCPKMS configures Google Cloud KMS custody for managed keys. Parent
// is the key ring resource, for example projects/P/locations/L/keyRings/R.
type ManagedKeysGCPKMS struct {
	Parent                string   `json:"parent,omitempty"`
	Endpoint              string   `json:"endpoint,omitempty"`
	AllowInsecureLoopback bool     `json:"allow_insecure_loopback,omitempty"`
	BearerToken           []byte   `json:"bearer_token,omitempty"`
	BearerTokenFile       string   `json:"bearer_token_file,omitempty"`
	PrivateEgressCIDRs    []string `json:"private_egress_cidrs,omitempty"`
}

// ManagedKeysPKCS11HSM configures a local PKCS#11 module for managed-key custody.
// UserPIN is []byte or file-backed because it authenticates the HSM session; it is
// wiped after startup wiring reads it.
type ManagedKeysPKCS11HSM struct {
	ModulePath     string `json:"module_path,omitempty"`
	TokenLabel     string `json:"token_label,omitempty"`
	UserPIN        []byte `json:"user_pin,omitempty"`
	UserPINFile    string `json:"user_pin_file,omitempty"`
	KeyLabelPrefix string `json:"key_label_prefix,omitempty"`
}

// ManagedKeysTPM2 configures a real TPM 2.0 device transport. Path may be a
// Linux TPM character device or a swtpm Unix socket. Hierarchy/key auth values
// remain byte-native and may be transferred to a child signer through private
// 0600 startup files that are removed after readiness.
type ManagedKeysTPM2 struct {
	Path                 string `json:"path,omitempty"`
	OwnerAuth            []byte `json:"owner_auth,omitempty"`
	OwnerAuthFile        string `json:"owner_auth_file,omitempty"`
	KeyAuth              []byte `json:"key_auth,omitempty"`
	KeyAuthFile          string `json:"key_auth_file,omitempty"`
	PersistentHandleBase uint32 `json:"persistent_handle_base,omitempty"`
}

func validateManagedKeys(m ManagedKeys) []error {
	if !m.Enabled {
		return nil
	}
	var errs []error
	listed := map[string]bool{}
	for i, raw := range m.Providers {
		provider := normalizeManagedKeyProvider(raw)
		switch {
		case provider == "":
			errs = append(errs, fmt.Errorf("managed_keys.providers[%d] is empty", i))
		case listed[provider]:
			errs = append(errs, fmt.Errorf("managed_keys.providers lists %q twice", provider))
		}
		listed[provider] = true
	}
	providers := m.EnabledProviders()
	if len(m.Providers) > 0 && strings.TrimSpace(m.Provider) != "" && !slices.Contains(providers, m.DefaultProvider()) {
		errs = append(errs, fmt.Errorf("managed_keys.provider %q must be one of managed_keys.providers", m.Provider))
	}
	for _, provider := range providers {
		errs = append(errs, validateManagedKeyProvider(m, provider)...)
	}
	pinned := map[string]bool{}
	for i, pin := range m.TenantProviders {
		if err := uuid.Validate(pin.TenantID); err != nil {
			errs = append(errs, fmt.Errorf("managed_keys.tenant_providers[%d].tenant_id must be a UUID", i))
		} else if pinned[pin.TenantID] {
			errs = append(errs, fmt.Errorf("managed_keys.tenant_providers pins tenant %s twice", pin.TenantID))
		}
		pinned[pin.TenantID] = true
		if !slices.Contains(providers, normalizeManagedKeyProvider(pin.Provider)) {
			errs = append(errs, fmt.Errorf("managed_keys.tenant_providers[%d].provider %q is not a configured provider", i, pin.Provider))
		}
	}
	return errs
}

// validateManagedKeyProvider checks one provider's block.
func validateManagedKeyProvider(m ManagedKeys, provider string) []error {
	var errs []error
	switch provider {
	case ManagedKeyProviderAWS:
		errs = append(errs, validateManagedKeyPrivateCIDRs("managed_keys.aws.private_egress_cidrs", m.AWS.PrivateEgressCIDRs)...)
		if strings.TrimSpace(m.AWS.Region) == "" {
			errs = append(errs, errors.New("managed_keys.aws.region is required when managed-key custody uses AWS KMS"))
		}
		if strings.TrimSpace(m.AWS.AccessKeyID) == "" {
			errs = append(errs, errors.New("managed_keys.aws.access_key_id is required when managed-key custody uses AWS KMS"))
		}
		if len(m.AWS.SecretAccessKey) == 0 && strings.TrimSpace(m.AWS.SecretAccessKeyFile) == "" {
			errs = append(errs, errors.New("managed_keys.aws.secret_access_key or managed_keys.aws.secret_access_key_file is required when managed-key custody uses AWS KMS"))
		}
		if m.AWS.Endpoint != "" {
			errs = append(errs, validateManagedKeyEndpoint("managed_keys.aws.endpoint", m.AWS.Endpoint, m.AWS.AllowInsecureLoopback)...)
		}
		if m.AWS.AllowInsecureLoopback && !netsec.IsInsecureLoopbackHTTPURL(m.AWS.Endpoint) {
			errs = append(errs, errors.New("managed_keys.aws.allow_insecure_loopback requires an HTTP localhost/loopback endpoint override"))
		}
		if len(m.AWS.SecretAccessKey) > 0 && strings.TrimSpace(m.AWS.SecretAccessKeyFile) != "" {
			errs = append(errs, errors.New("managed_keys.aws.secret_access_key and secret_access_key_file are mutually exclusive"))
		}
		if len(m.AWS.SessionToken) > 0 && strings.TrimSpace(m.AWS.SessionTokenFile) != "" {
			errs = append(errs, errors.New("managed_keys.aws.session_token and session_token_file are mutually exclusive"))
		}
	case ManagedKeyProviderAzureKeyVault:
		errs = append(errs, validateManagedKeyPrivateCIDRs("managed_keys.azure.private_egress_cidrs", m.Azure.PrivateEgressCIDRs)...)
		if strings.TrimSpace(m.Azure.VaultURL) == "" {
			errs = append(errs, errors.New("managed_keys.azure.vault_url is required when managed-key custody uses Azure Key Vault HSM"))
		} else {
			errs = append(errs, validateManagedKeyEndpoint("managed_keys.azure.vault_url", m.Azure.VaultURL, m.Azure.AllowInsecureLoopback)...)
		}
		if len(m.Azure.BearerToken) == 0 && strings.TrimSpace(m.Azure.BearerTokenFile) == "" {
			errs = append(errs, errors.New("managed_keys.azure.bearer_token or managed_keys.azure.bearer_token_file is required when managed-key custody uses Azure Key Vault HSM"))
		}
		if m.Azure.Endpoint != "" {
			errs = append(errs, validateManagedKeyEndpoint("managed_keys.azure.endpoint", m.Azure.Endpoint, m.Azure.AllowInsecureLoopback)...)
		}
		if m.Azure.AllowInsecureLoopback &&
			!netsec.IsInsecureLoopbackHTTPURL(m.Azure.VaultURL) &&
			!netsec.IsInsecureLoopbackHTTPURL(m.Azure.Endpoint) {
			errs = append(errs, errors.New("managed_keys.azure.allow_insecure_loopback requires an HTTP localhost/loopback vault_url or endpoint override"))
		}
		if len(m.Azure.BearerToken) > 0 && strings.TrimSpace(m.Azure.BearerTokenFile) != "" {
			errs = append(errs, errors.New("managed_keys.azure.bearer_token and bearer_token_file are mutually exclusive"))
		}
	case ManagedKeyProviderGCPKMS:
		errs = append(errs, validateManagedKeyPrivateCIDRs("managed_keys.gcp.private_egress_cidrs", m.GCP.PrivateEgressCIDRs)...)
		if strings.TrimSpace(m.GCP.Parent) == "" {
			errs = append(errs, errors.New("managed_keys.gcp.parent is required when managed-key custody uses GCP Cloud KMS"))
		}
		if len(m.GCP.BearerToken) == 0 && strings.TrimSpace(m.GCP.BearerTokenFile) == "" {
			errs = append(errs, errors.New("managed_keys.gcp.bearer_token or managed_keys.gcp.bearer_token_file is required when managed-key custody uses GCP Cloud KMS"))
		}
		if m.GCP.Endpoint != "" {
			errs = append(errs, validateManagedKeyEndpoint("managed_keys.gcp.endpoint", m.GCP.Endpoint, m.GCP.AllowInsecureLoopback)...)
		}
		if m.GCP.AllowInsecureLoopback && !netsec.IsInsecureLoopbackHTTPURL(m.GCP.Endpoint) {
			errs = append(errs, errors.New("managed_keys.gcp.allow_insecure_loopback requires an HTTP localhost/loopback endpoint override"))
		}
		if len(m.GCP.BearerToken) > 0 && strings.TrimSpace(m.GCP.BearerTokenFile) != "" {
			errs = append(errs, errors.New("managed_keys.gcp.bearer_token and bearer_token_file are mutually exclusive"))
		}
	case ManagedKeyProviderPKCS11:
		if strings.TrimSpace(m.PKCS11.ModulePath) == "" {
			errs = append(errs, errors.New("managed_keys.pkcs11.module_path is required when managed-key custody uses PKCS#11"))
		}
		if strings.TrimSpace(m.PKCS11.TokenLabel) == "" {
			errs = append(errs, errors.New("managed_keys.pkcs11.token_label is required when managed-key custody uses PKCS#11"))
		}
		if len(m.PKCS11.UserPIN) == 0 && strings.TrimSpace(m.PKCS11.UserPINFile) == "" {
			errs = append(errs, errors.New("managed_keys.pkcs11.user_pin or managed_keys.pkcs11.user_pin_file is required when managed-key custody uses PKCS#11"))
		}
		if len(m.PKCS11.UserPIN) > 0 && strings.TrimSpace(m.PKCS11.UserPINFile) != "" {
			errs = append(errs, errors.New("managed_keys.pkcs11.user_pin and user_pin_file are mutually exclusive"))
		}
	case ManagedKeyProviderTPM2:
		if strings.TrimSpace(m.TPM2.Path) == "" {
			errs = append(errs, errors.New("managed_keys.tpm2.path is required when managed-key custody uses TPM 2.0"))
		}
		if len(m.TPM2.OwnerAuth) > 0 && strings.TrimSpace(m.TPM2.OwnerAuthFile) != "" {
			errs = append(errs, errors.New("managed_keys.tpm2.owner_auth and owner_auth_file are mutually exclusive"))
		}
		if len(m.TPM2.KeyAuth) > 0 && strings.TrimSpace(m.TPM2.KeyAuthFile) != "" {
			errs = append(errs, errors.New("managed_keys.tpm2.key_auth and key_auth_file are mutually exclusive"))
		}
	case ManagedKeyProviderYubiHSM2:
		if strings.TrimSpace(m.YubiHSM2.ModulePath) == "" {
			errs = append(errs, errors.New("managed_keys.yubihsm2.module_path is required for the Yubico PKCS#11 module"))
		}
		if strings.TrimSpace(m.YubiHSM2.TokenLabel) == "" {
			errs = append(errs, errors.New("managed_keys.yubihsm2.token_label is required"))
		}
		if len(m.YubiHSM2.UserPIN) == 0 && strings.TrimSpace(m.YubiHSM2.UserPINFile) == "" {
			errs = append(errs, errors.New("managed_keys.yubihsm2.user_pin or user_pin_file is required"))
		}
		if len(m.YubiHSM2.UserPIN) > 0 && strings.TrimSpace(m.YubiHSM2.UserPINFile) != "" {
			errs = append(errs, errors.New("managed_keys.yubihsm2.user_pin and user_pin_file are mutually exclusive"))
		}
	default:
		errs = append(errs, fmt.Errorf("managed-key provider %q is invalid (want %q, %q, %q, %q, %q, or %q)", provider, ManagedKeyProviderAWS, ManagedKeyProviderAzureKeyVault, ManagedKeyProviderGCPKMS, ManagedKeyProviderPKCS11, ManagedKeyProviderTPM2, ManagedKeyProviderYubiHSM2))
	}
	return errs
}

func validateManagedKeyPrivateCIDRs(label string, values []string) []error {
	var errs []error
	for _, raw := range values {
		if _, err := netsec.ParseEgressAllowPrefix(raw); err != nil {
			errs = append(errs, fmt.Errorf("%s contains invalid CIDR %q: %w", label, raw, err))
		}
	}
	return errs
}

func validateManagedKeyEndpoint(label, raw string, allowInsecureLoopback bool) []error {
	if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(raw, allowInsecureLoopback); err != nil {
		return []error{fmt.Errorf("%s %q: %w", label, raw, err)}
	}
	return nil
}
