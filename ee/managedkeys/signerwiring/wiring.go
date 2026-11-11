// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package signerwiring owns the Enterprise-only construction of cloud KMS and
// hardware managed-key providers inside the isolated signer process, and of the
// HSM-backed tenant domain KEK custody (TenantKEKOption, A123). It is reached
// only through cmd/trstctl-signer's tagged EE attach seam after the BYOK
// license check. This package starts no server and imports no SQL or event bus.
package signerwiring

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"trstctl.com/trstctl/internal/cloudauth"
	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/kms/awskms"
	"trstctl.com/trstctl/internal/kms/azurekv"
	"trstctl.com/trstctl/internal/kms/gcpkms"
	"trstctl.com/trstctl/internal/kms/kmsconn"
	"trstctl.com/trstctl/internal/kms/pkcs11"
	"trstctl.com/trstctl/internal/kms/tpm"
	"trstctl.com/trstctl/internal/kms/yubihsm"
	"trstctl.com/trstctl/internal/signing"
)

const maxManagedKeyConfigBytes = 1 << 20

const (
	providerAWS     = "aws"
	providerAzure   = "azure-key-vault"
	providerGCP     = "gcp-kms"
	providerPKCS11  = "pkcs11"
	providerTPM2    = "tpm2"
	providerYubiHSM = "yubihsm2"
)

// These signer-local JSON types intentionally do not import internal/config.
// That control-plane package imports github.com/google/uuid, whose SQL scanner
// support links database/sql/driver and violates the sacred signer closure.
type managedKeyConfig struct {
	Enabled  bool   `json:"enabled,omitempty"`
	Provider string `json:"provider,omitempty"`
	// Providers is every provider the signer holds at once (A199); empty
	// means Provider alone.
	Providers []string `json:"providers,omitempty"`
	// TenantProviders is control-plane policy. A shared configuration may
	// carry it; the signer holds every listed provider regardless.
	TenantProviders []tenantProviderPin `json:"tenant_providers,omitempty"`
	AWS             awsConfig           `json:"aws,omitempty"`
	Azure           cloudTokenConfig    `json:"azure,omitempty"`
	GCP             gcpConfig           `json:"gcp,omitempty"`
	PKCS11          pkcs11Config        `json:"pkcs11,omitempty"`
	TPM2            tpm2Config          `json:"tpm2,omitempty"`
	YubiHSM2        pkcs11Config        `json:"yubihsm2,omitempty"`
}

type tenantProviderPin struct {
	TenantID string `json:"tenant_id"`
	Provider string `json:"provider"`
}

type awsConfig struct {
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

type cloudTokenConfig struct {
	VaultURL              string                 `json:"vault_url,omitempty"`
	Endpoint              string                 `json:"endpoint,omitempty"`
	AllowInsecureLoopback bool                   `json:"allow_insecure_loopback,omitempty"`
	BearerToken           []byte                 `json:"bearer_token,omitempty"`
	BearerTokenFile       string                 `json:"bearer_token_file,omitempty"`
	WorkloadIdentity      *azureWorkloadIdentity `json:"workload_identity,omitempty"`
	PrivateEgressCIDRs    []string               `json:"private_egress_cidrs,omitempty"`
}

// azureWorkloadIdentity mirrors config.ManagedKeysAzureWorkloadIdentity (A169).
type azureWorkloadIdentity struct {
	TenantID           string `json:"tenant_id,omitempty"`
	ClientID           string `json:"client_id,omitempty"`
	FederatedTokenFile string `json:"federated_token_file,omitempty"`
	AuthorityHost      string `json:"authority_host,omitempty"`
	Scope              string `json:"scope,omitempty"`
}

type gcpConfig struct {
	Parent                string               `json:"parent,omitempty"`
	Endpoint              string               `json:"endpoint,omitempty"`
	AllowInsecureLoopback bool                 `json:"allow_insecure_loopback,omitempty"`
	BearerToken           []byte               `json:"bearer_token,omitempty"`
	BearerTokenFile       string               `json:"bearer_token_file,omitempty"`
	WorkloadIdentity      *gcpWorkloadIdentity `json:"workload_identity,omitempty"`
	PrivateEgressCIDRs    []string             `json:"private_egress_cidrs,omitempty"`
}

// gcpWorkloadIdentity mirrors config.ManagedKeysGCPWorkloadIdentity (A169-L1).
type gcpWorkloadIdentity struct {
	Audience              string `json:"audience,omitempty"`
	SubjectTokenFile      string `json:"subject_token_file,omitempty"`
	ServiceAccount        string `json:"service_account,omitempty"`
	STSEndpoint           string `json:"sts_endpoint,omitempty"`
	ImpersonationEndpoint string `json:"impersonation_endpoint,omitempty"`
}

type pkcs11Config struct {
	ModulePath     string `json:"module_path,omitempty"`
	TokenLabel     string `json:"token_label,omitempty"`
	UserPIN        []byte `json:"user_pin,omitempty"`
	UserPINFile    string `json:"user_pin_file,omitempty"`
	KeyLabelPrefix string `json:"key_label_prefix,omitempty"`
}

type tpm2Config struct {
	Path                 string `json:"path,omitempty"`
	OwnerAuth            []byte `json:"owner_auth,omitempty"`
	OwnerAuthFile        string `json:"owner_auth_file,omitempty"`
	KeyAuth              []byte `json:"key_auth,omitempty"`
	KeyAuthFile          string `json:"key_auth_file,omitempty"`
	PersistentHandleBase uint32 `json:"persistent_handle_base,omitempty"`
}

// ProviderOption decodes signer-local configuration, constructs every listed
// licensed provider (one when only Provider is set), and binds them to the
// signer's durable managed-key runtime, which keeps each key's provider in its
// journal. Credential values must be file references; inline values fail
// closed.
func ProviderOption(path, journalDir string) (signing.ServerOption, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path is the signer operator's explicit local configuration file, never remote input (CWE-22).
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(raw)
	if len(raw) > maxManagedKeyConfigBytes {
		return nil, fmt.Errorf("managed-key config exceeds %d bytes", maxManagedKeyConfigBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var cfg managedKeyConfig
	decodeErr := dec.Decode(&cfg)
	// Decode may allocate inline credential fields even when it later fails on a
	// trailing/unknown value. Inline credentials are forbidden, but rejection
	// must still wipe every authority-bearing byte allocation (AN-8).
	defer wipeConfigSecrets(&cfg)
	if decodeErr != nil {
		return nil, fmt.Errorf("decode managed-key config: %w", decodeErr)
	}
	if err := ensureConfigEOF(dec); err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, fmt.Errorf("managed-key config is not enabled")
	}
	if strings.TrimSpace(journalDir) == "" {
		return nil, fmt.Errorf("managed-key provider requires --keystore for a durable idempotency journal")
	}
	providers := map[string]crypto.RemoteKeyLifecycle{}
	for _, name := range enabledProviders(cfg) {
		one := cfg
		one.Provider = name
		providerName, implementation, err := provider(one)
		if err != nil {
			return nil, fmt.Errorf("managed-key provider %s: %w", name, err)
		}
		if _, dup := providers[providerName]; dup {
			return nil, fmt.Errorf("managed-key config lists provider %s twice", providerName)
		}
		providers[providerName] = implementation
	}
	return signing.WithManagedKeyProviders(journalDir, providers), nil
}

// enabledProviders is Providers when set, else Provider alone (AWS KMS when
// that is empty too), lowercase and trimmed.
func enabledProviders(cfg managedKeyConfig) []string {
	var out []string
	for _, raw := range cfg.Providers {
		if name := strings.ToLower(strings.TrimSpace(raw)); name != "" {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		name := strings.ToLower(strings.TrimSpace(cfg.Provider))
		if name == "" {
			name = providerAWS
		}
		out = append(out, name)
	}
	return out
}

func wipeConfigSecrets(cfg *managedKeyConfig) {
	if cfg == nil {
		return
	}
	for _, value := range [][]byte{
		cfg.AWS.SecretAccessKey,
		cfg.AWS.SessionToken,
		cfg.Azure.BearerToken,
		cfg.GCP.BearerToken,
		cfg.PKCS11.UserPIN,
		cfg.TPM2.OwnerAuth,
		cfg.TPM2.KeyAuth,
		cfg.YubiHSM2.UserPIN,
	} {
		secret.Wipe(value)
	}
	cfg.AWS.SecretAccessKey = nil
	cfg.AWS.SessionToken = nil
	cfg.Azure.BearerToken = nil
	cfg.GCP.BearerToken = nil
	cfg.PKCS11.UserPIN = nil
	cfg.TPM2.OwnerAuth = nil
	cfg.TPM2.KeyAuth = nil
	cfg.YubiHSM2.UserPIN = nil
}

func ensureConfigEOF(dec *json.Decoder) error {
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("managed-key config contains more than one JSON document")
		}
		return fmt.Errorf("decode managed-key config trailer: %w", err)
	}
	return nil
}

func provider(cfg managedKeyConfig) (string, crypto.RemoteKeyLifecycle, error) {
	providerName := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if providerName == "" {
		providerName = providerAWS
	}
	switch providerName {
	case providerAWS:
		if err := kmsconn.ValidateEndpoints("aws managed-key", cfg.AWS.AllowInsecureLoopback, cfg.AWS.Endpoint); err != nil {
			return "", nil, err
		}
		secretKey, wipeSecret, err := credential("aws secret access key", cfg.AWS.SecretAccessKey, cfg.AWS.SecretAccessKeyFile, true)
		if err != nil {
			return "", nil, err
		}
		defer wipeSecret()
		session, wipeSession, err := credential("aws session token", cfg.AWS.SessionToken, cfg.AWS.SessionTokenFile, false)
		if err != nil {
			return "", nil, err
		}
		defer wipeSession()
		httpClient, err := kmsconn.EgressClient(cfg.AWS.PrivateEgressCIDRs, cfg.AWS.Endpoint, cfg.AWS.AllowInsecureLoopback)
		if err != nil {
			return "", nil, fmt.Errorf("aws managed-key egress: %w", err)
		}
		opts := []awskms.Option{awskms.WithHTTPClient(httpClient)}
		if cfg.AWS.Endpoint != "" {
			opts = append(opts, awskms.WithEndpoint(cfg.AWS.Endpoint))
		}
		backend, err := awskms.NewSecure(cfg.AWS.Region, awskms.Credentials{
			AccessKeyID: cfg.AWS.AccessKeyID, SecretAccessKey: secretKey, SessionToken: session,
		}, opts...)
		return "aws-kms", backend, err
	case providerAzure:
		if err := kmsconn.ValidateEndpoints("azure managed-key", cfg.Azure.AllowInsecureLoopback, cfg.Azure.VaultURL, cfg.Azure.Endpoint); err != nil {
			return "", nil, err
		}
		creds, wipe, err := azureCredentials(cfg.Azure)
		if err != nil {
			return "", nil, err
		}
		defer wipe()
		azureEndpoint := cfg.Azure.Endpoint
		if strings.TrimSpace(azureEndpoint) == "" {
			azureEndpoint = cfg.Azure.VaultURL
		}
		httpClient, err := kmsconn.EgressClient(cfg.Azure.PrivateEgressCIDRs, azureEndpoint, cfg.Azure.AllowInsecureLoopback)
		if err != nil {
			return "", nil, fmt.Errorf("azure managed-key egress: %w", err)
		}
		opts := []azurekv.Option{azurekv.WithHTTPClient(httpClient)}
		if cfg.Azure.Endpoint != "" {
			opts = append(opts, azurekv.WithEndpoint(cfg.Azure.Endpoint))
		}
		backend, err := azurekv.NewSecure(cfg.Azure.VaultURL, creds, opts...)
		return "azure-key-vault", backend, err
	case providerGCP:
		if err := kmsconn.ValidateEndpoints("gcp managed-key", cfg.GCP.AllowInsecureLoopback, cfg.GCP.Endpoint); err != nil {
			return "", nil, err
		}
		creds, wipe, err := gcpCredentials(cfg.GCP)
		if err != nil {
			return "", nil, err
		}
		defer wipe()
		httpClient, err := kmsconn.EgressClient(cfg.GCP.PrivateEgressCIDRs, cfg.GCP.Endpoint, cfg.GCP.AllowInsecureLoopback)
		if err != nil {
			return "", nil, fmt.Errorf("gcp managed-key egress: %w", err)
		}
		opts := []gcpkms.Option{gcpkms.WithHTTPClient(httpClient)}
		if cfg.GCP.Endpoint != "" {
			opts = append(opts, gcpkms.WithEndpoint(cfg.GCP.Endpoint))
		}
		backend, err := gcpkms.NewSecure(cfg.GCP.Parent, creds, opts...)
		return "gcp-kms", backend, err
	case providerPKCS11:
		pin, wipe, err := credential("pkcs11 user PIN", cfg.PKCS11.UserPIN, cfg.PKCS11.UserPINFile, true)
		if err != nil {
			return "", nil, err
		}
		defer wipe()
		session, err := pkcs11.OpenModuleSession(pkcs11.ModuleConfig{
			ModulePath: cfg.PKCS11.ModulePath, TokenLabel: cfg.PKCS11.TokenLabel,
			UserPIN: pin, KeyLabelPrefix: cfg.PKCS11.KeyLabelPrefix,
		})
		if err != nil {
			return "", nil, err
		}
		return "pkcs11", pkcs11.New(session), nil
	case providerTPM2:
		owner, wipeOwner, err := credential("tpm2 owner auth", cfg.TPM2.OwnerAuth, cfg.TPM2.OwnerAuthFile, false)
		if err != nil {
			return "", nil, err
		}
		defer wipeOwner()
		keyAuth, wipeKey, err := credential("tpm2 key auth", cfg.TPM2.KeyAuth, cfg.TPM2.KeyAuthFile, false)
		if err != nil {
			return "", nil, err
		}
		defer wipeKey()
		device, err := tpm.OpenDevice(tpm.DeviceConfig{
			Path: cfg.TPM2.Path, OwnerAuth: owner, KeyAuth: keyAuth,
			PersistentHandleBase: cfg.TPM2.PersistentHandleBase,
		})
		if err != nil {
			return "", nil, err
		}
		return "tpm2", tpm.New(device), nil
	case providerYubiHSM:
		pin, wipe, err := credential("yubihsm2 user PIN", cfg.YubiHSM2.UserPIN, cfg.YubiHSM2.UserPINFile, true)
		if err != nil {
			return "", nil, err
		}
		defer wipe()
		connector, err := yubihsm.OpenPKCS11Connector(yubihsm.PKCS11Config{
			ModulePath: cfg.YubiHSM2.ModulePath, TokenLabel: cfg.YubiHSM2.TokenLabel,
			UserPIN: pin, KeyLabelPrefix: cfg.YubiHSM2.KeyLabelPrefix,
		})
		if err != nil {
			return "", nil, err
		}
		return "yubihsm2", yubihsm.New(connector), nil
	default:
		return "", nil, fmt.Errorf("unsupported signer managed-key provider %q", cfg.Provider)
	}
}

func credential(name string, inline []byte, file string, required bool) ([]byte, func(), error) {
	if len(inline) > 0 {
		return nil, func() {}, fmt.Errorf("%s must use a file reference in trstctl-signer config; inline secrets are forbidden", name)
	}
	return kmsconn.CredentialFile(name, file, required)
}

// azureCredentials returns the Key Vault credential the configuration names:
// the static bearer token file, or a workload identity token source that
// exchanges the platform's projected federated token for short-lived Entra
// tokens (A169). The two are exclusive.
func azureCredentials(cfg cloudTokenConfig) (azurekv.Credentials, func(), error) {
	wi := cfg.WorkloadIdentity
	if wi == nil {
		token, wipe, err := credential("azure bearer token", cfg.BearerToken, cfg.BearerTokenFile, true)
		if err != nil {
			return azurekv.Credentials{}, func() {}, err
		}
		return azurekv.Credentials{BearerToken: token}, wipe, nil
	}
	if len(cfg.BearerToken) > 0 || strings.TrimSpace(cfg.BearerTokenFile) != "" {
		return azurekv.Credentials{}, func() {}, fmt.Errorf("azure managed-key: workload_identity replaces the static bearer token; set one, not both")
	}
	host := strings.TrimSpace(wi.AuthorityHost)
	if host == "" {
		host = "https://login.microsoftonline.com"
	}
	// EgressClient admits the authority over HTTPS, or plain HTTP only on an
	// allowed loopback stand-in, and keeps the SSRF guard on every redirect.
	client, err := kmsconn.EgressClient(cfg.PrivateEgressCIDRs, host, cfg.AllowInsecureLoopback)
	if err != nil {
		return azurekv.Credentials{}, func() {}, fmt.Errorf("azure workload identity egress: %w", err)
	}
	scope := strings.TrimSpace(wi.Scope)
	if scope == "" {
		scope = azureKeyVaultScope(cfg.VaultURL)
	}
	source, err := cloudauth.NewAzureFederatedTokenSource(cloudauth.AzureFederatedTokenSourceConfig{
		TenantID: wi.TenantID, ClientID: wi.ClientID, FederatedTokenFile: wi.FederatedTokenFile,
		AuthorityHost: host, Scope: scope, Doer: client,
	})
	if err != nil {
		return azurekv.Credentials{}, func() {}, fmt.Errorf("azure managed-key: %w", err)
	}
	return azurekv.Credentials{TokenSource: source}, func() {}, nil
}

// gcpCredentials returns the Cloud KMS credential the configuration names: the
// static bearer token file, or a workload identity token source that exchanges
// the platform's projected OIDC token at GCP Security Token Service, and
// optionally impersonates a service account, for short-lived access tokens
// (A169-L1). The two are exclusive.
func gcpCredentials(cfg gcpConfig) (gcpkms.Credentials, func(), error) {
	wi := cfg.WorkloadIdentity
	if wi == nil {
		token, wipe, err := credential("gcp bearer token", cfg.BearerToken, cfg.BearerTokenFile, true)
		if err != nil {
			return gcpkms.Credentials{}, func() {}, err
		}
		return gcpkms.Credentials{BearerToken: token}, wipe, nil
	}
	if len(cfg.BearerToken) > 0 || strings.TrimSpace(cfg.BearerTokenFile) != "" {
		return gcpkms.Credentials{}, func() {}, fmt.Errorf("gcp managed-key: workload_identity replaces the static bearer token; set one, not both")
	}
	sts := strings.TrimSpace(wi.STSEndpoint)
	if sts == "" {
		sts = cloudauth.DefaultGCPSTSEndpoint
	}
	// EgressClient admits each endpoint over HTTPS, or plain HTTP only on an
	// allowed loopback stand-in, and keeps the SSRF guard on every redirect.
	stsClient, err := kmsconn.EgressClient(cfg.PrivateEgressCIDRs, sts, cfg.AllowInsecureLoopback)
	if err != nil {
		return gcpkms.Credentials{}, func() {}, fmt.Errorf("gcp workload identity egress: %w", err)
	}
	impersonation := strings.TrimSpace(wi.ImpersonationEndpoint)
	if impersonation == "" && strings.TrimSpace(wi.ServiceAccount) != "" {
		impersonation = cloudauth.GCPImpersonationEndpoint(wi.ServiceAccount)
	}
	var impersonationClient cloudhttp.Doer
	if impersonation != "" {
		client, err := kmsconn.EgressClient(cfg.PrivateEgressCIDRs, impersonation, cfg.AllowInsecureLoopback)
		if err != nil {
			return gcpkms.Credentials{}, func() {}, fmt.Errorf("gcp workload identity egress: %w", err)
		}
		impersonationClient = client
	}
	source, err := cloudauth.NewGCPWorkloadIdentityTokenSource(cloudauth.GCPWorkloadIdentityTokenSourceConfig{
		Audience: wi.Audience, SubjectTokenFile: wi.SubjectTokenFile, STSEndpoint: sts,
		ServiceAccount: wi.ServiceAccount, ImpersonationEndpoint: impersonation,
		Doer: stsClient, ImpersonationDoer: impersonationClient,
	})
	if err != nil {
		return gcpkms.Credentials{}, func() {}, fmt.Errorf("gcp managed-key: %w", err)
	}
	return gcpkms.Credentials{TokenSource: source}, func() {}, nil
}

// azureKeyVaultScope is the token scope the vault URL implies: Managed HSM
// pools have their own resource; every other vault is Key Vault.
func azureKeyVaultScope(vaultURL string) string {
	if strings.Contains(strings.ToLower(vaultURL), ".managedhsm.") {
		return "https://managedhsm.azure.net/.default"
	}
	return "https://vault.azure.net/.default"
}
