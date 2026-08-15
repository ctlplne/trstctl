// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package signerwiring owns the Enterprise-only construction of cloud KMS and
// hardware managed-key providers inside the isolated signer process. It is
// reached only through cmd/trstctl-signer's tagged EE attach seam after the BYOK
// license check. This package starts no server and imports no SQL or event bus.
package signerwiring

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/kms/awskms"
	"trstctl.com/trstctl/internal/kms/azurekv"
	"trstctl.com/trstctl/internal/kms/gcpkms"
	"trstctl.com/trstctl/internal/kms/pkcs11"
	"trstctl.com/trstctl/internal/kms/tpm"
	"trstctl.com/trstctl/internal/kms/yubihsm"
	"trstctl.com/trstctl/internal/netsec"
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
	Enabled  bool             `json:"enabled,omitempty"`
	Provider string           `json:"provider,omitempty"`
	AWS      awsConfig        `json:"aws,omitempty"`
	Azure    cloudTokenConfig `json:"azure,omitempty"`
	GCP      gcpConfig        `json:"gcp,omitempty"`
	PKCS11   pkcs11Config     `json:"pkcs11,omitempty"`
	TPM2     tpm2Config       `json:"tpm2,omitempty"`
	YubiHSM2 pkcs11Config     `json:"yubihsm2,omitempty"`
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
	VaultURL              string   `json:"vault_url,omitempty"`
	Endpoint              string   `json:"endpoint,omitempty"`
	AllowInsecureLoopback bool     `json:"allow_insecure_loopback,omitempty"`
	BearerToken           []byte   `json:"bearer_token,omitempty"`
	BearerTokenFile       string   `json:"bearer_token_file,omitempty"`
	PrivateEgressCIDRs    []string `json:"private_egress_cidrs,omitempty"`
}

type gcpConfig struct {
	Parent                string   `json:"parent,omitempty"`
	Endpoint              string   `json:"endpoint,omitempty"`
	AllowInsecureLoopback bool     `json:"allow_insecure_loopback,omitempty"`
	BearerToken           []byte   `json:"bearer_token,omitempty"`
	BearerTokenFile       string   `json:"bearer_token_file,omitempty"`
	PrivateEgressCIDRs    []string `json:"private_egress_cidrs,omitempty"`
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

// ProviderOption decodes signer-local configuration, constructs exactly one
// licensed provider, and binds it to the signer's durable managed-key runtime.
// Credential values must be file references; inline values fail closed.
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
	providerName, implementation, err := provider(cfg)
	if err != nil {
		return nil, err
	}
	return signing.WithManagedKeyProviders(journalDir, map[string]crypto.RemoteKeyLifecycle{providerName: implementation}), nil
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
		if err := validateManagedKeyEndpoints("aws", cfg.AWS.AllowInsecureLoopback, cfg.AWS.Endpoint); err != nil {
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
		httpClient, err := egressClient(cfg.AWS.PrivateEgressCIDRs, cfg.AWS.Endpoint, cfg.AWS.AllowInsecureLoopback)
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
		if err := validateManagedKeyEndpoints("azure", cfg.Azure.AllowInsecureLoopback, cfg.Azure.VaultURL, cfg.Azure.Endpoint); err != nil {
			return "", nil, err
		}
		token, wipe, err := credential("azure bearer token", cfg.Azure.BearerToken, cfg.Azure.BearerTokenFile, true)
		if err != nil {
			return "", nil, err
		}
		defer wipe()
		azureEndpoint := cfg.Azure.Endpoint
		if strings.TrimSpace(azureEndpoint) == "" {
			azureEndpoint = cfg.Azure.VaultURL
		}
		httpClient, err := egressClient(cfg.Azure.PrivateEgressCIDRs, azureEndpoint, cfg.Azure.AllowInsecureLoopback)
		if err != nil {
			return "", nil, fmt.Errorf("azure managed-key egress: %w", err)
		}
		opts := []azurekv.Option{azurekv.WithHTTPClient(httpClient)}
		if cfg.Azure.Endpoint != "" {
			opts = append(opts, azurekv.WithEndpoint(cfg.Azure.Endpoint))
		}
		backend, err := azurekv.NewSecure(cfg.Azure.VaultURL, azurekv.Credentials{BearerToken: token}, opts...)
		return "azure-key-vault", backend, err
	case providerGCP:
		if err := validateManagedKeyEndpoints("gcp", cfg.GCP.AllowInsecureLoopback, cfg.GCP.Endpoint); err != nil {
			return "", nil, err
		}
		token, wipe, err := credential("gcp bearer token", cfg.GCP.BearerToken, cfg.GCP.BearerTokenFile, true)
		if err != nil {
			return "", nil, err
		}
		defer wipe()
		httpClient, err := egressClient(cfg.GCP.PrivateEgressCIDRs, cfg.GCP.Endpoint, cfg.GCP.AllowInsecureLoopback)
		if err != nil {
			return "", nil, fmt.Errorf("gcp managed-key egress: %w", err)
		}
		opts := []gcpkms.Option{gcpkms.WithHTTPClient(httpClient)}
		if cfg.GCP.Endpoint != "" {
			opts = append(opts, gcpkms.WithEndpoint(cfg.GCP.Endpoint))
		}
		backend, err := gcpkms.NewSecure(cfg.GCP.Parent, gcpkms.Credentials{BearerToken: token}, opts...)
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

func validateManagedKeyEndpoints(provider string, allowInsecureLoopback bool, endpoints ...string) error {
	usedInsecureLoopback := false
	for _, endpoint := range endpoints {
		if strings.TrimSpace(endpoint) == "" {
			continue
		}
		if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(endpoint, allowInsecureLoopback); err != nil {
			return fmt.Errorf("%s managed-key endpoint: %w", provider, err)
		}
		usedInsecureLoopback = usedInsecureLoopback || netsec.IsInsecureLoopbackHTTPURL(endpoint)
	}
	if allowInsecureLoopback && !usedInsecureLoopback {
		return fmt.Errorf("%s managed-key allow_insecure_loopback requires an HTTP localhost/loopback endpoint", provider)
	}
	return nil
}

func egressClient(rawCIDRs []string, endpoint string, allowInsecureLoopback bool) (*http.Client, error) {
	allowPlaintext := allowInsecureLoopback && netsec.IsInsecureLoopbackHTTPURL(endpoint)
	if strings.TrimSpace(endpoint) != "" {
		if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(endpoint, allowPlaintext); err != nil {
			return nil, err
		}
	}
	if allowPlaintext {
		return netsec.InsecureLoopbackClient(30 * time.Second), nil
	}
	prefixes := make([]netip.Prefix, 0, len(rawCIDRs))
	for _, raw := range rawCIDRs {
		prefix, err := netsec.ParseEgressAllowPrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid private egress CIDR %q: %w", raw, err)
		}
		prefixes = append(prefixes, prefix)
	}
	client := netsec.SafeClientWithOptions(30*time.Second, netsec.SafeClientOptions{AllowPrivateCIDRs: prefixes})
	previousRedirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req == nil || req.URL == nil {
			return fmt.Errorf("managed-key redirect is missing a URL")
		}
		if err := netsec.ValidateHTTPSOrInsecureLoopbackURL(req.URL.String(), false); err != nil {
			return err
		}
		return previousRedirect(req, via)
	}
	return client, nil
}

func credential(name string, inline []byte, file string, required bool) ([]byte, func(), error) {
	if len(inline) > 0 {
		return nil, func() {}, fmt.Errorf("%s must use a file reference in trstctl-signer config; inline secrets are forbidden", name)
	}
	if strings.TrimSpace(file) == "" {
		if required {
			return nil, func() {}, fmt.Errorf("%s file is required", name)
		}
		return nil, func() {}, nil
	}
	raw, err := readCredentialFile(file)
	if err != nil {
		return nil, func() {}, fmt.Errorf("read %s file: %w", name, err)
	}
	return lockCredentialBytes(name, raw, required)
}

// readCredentialFile reads a managed-key credential through a handle on its
// parent directory instead of by name. These files carry authority-bearing key
// material (cloud tokens, HSM PINs, TPM auth) that the isolated signer loads at
// startup, so a symlink swapped in at the final component must not be able to
// redirect the read somewhere else between the operator's configuration and the
// open. os.Root resolves every component at the syscall layer and refuses one
// that leaves the directory (CWE-22, CWE-367).
func readCredentialFile(path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.ReadFile(filepath.Base(path))
}

func lockCredentialBytes(name string, fileBuffer []byte, required bool) ([]byte, func(), error) {
	// bytes.TrimSpace returns a subslice. Clone the useful payload first, then
	// wipe the complete os.ReadFile allocation so bytes outside that subslice do
	// not remain in the signer heap.
	payload := bytes.Clone(bytes.TrimSpace(fileBuffer))
	secret.Wipe(fileBuffer)
	if required && len(payload) == 0 {
		secret.Wipe(payload)
		return nil, func() {}, fmt.Errorf("%s file is empty", name)
	}
	locked, err := secret.NewFrom(payload)
	secret.Wipe(payload)
	if err != nil {
		return nil, func() {}, fmt.Errorf("lock %s: %w", name, err)
	}
	return locked.Bytes(), locked.Destroy, nil
}
