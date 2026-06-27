package managedkeys

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/egress"
	"trstctl.com/trstctl/internal/kms/awskms"
	"trstctl.com/trstctl/internal/server"
)

// FactoryFromConfig assembles the licensed managed-key service factory from the
// operator's BYOK/HSM custody config. A disabled config returns nil, nil so a
// licensed deployment with BYOK off still leaves the API surface hidden.
func FactoryFromConfig(ctx context.Context, cfg config.ManagedKeys, guard *egress.Guard) (server.ManagedKeyServiceFactory, error) {
	backend, err := CustodyFromConfig(ctx, cfg, guard)
	if err != nil {
		return nil, err
	}
	if backend == nil {
		return nil, nil
	}
	return NewFactory(backend), nil
}

// CustodyFromConfig assembles the remote-custody backend once at startup and
// injects it behind crypto.RemoteKeyLifecycle. This is deliberately the generic
// compile-time interface + dependency-injection pattern used by crypto.Signer,
// Java JCA, OpenSSL ENGINE, and PKCS#11.
func CustodyFromConfig(_ context.Context, cfg config.ManagedKeys, guard *egress.Guard) (crypto.RemoteKeyLifecycle, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if provider == "" {
		provider = config.ManagedKeyProviderAWS
	}
	switch provider {
	case config.ManagedKeyProviderAWS:
		return awsManagedKeyCustodyFromConfig(cfg.AWS, guard)
	default:
		return nil, fmt.Errorf("managed-key custody provider %q is not supported", cfg.Provider)
	}
}

func awsManagedKeyCustodyFromConfig(cfg config.ManagedKeysAWSKMS, guard *egress.Guard) (crypto.RemoteKeyLifecycle, error) {
	secretAccessKey, wipeSecret, err := managedKeySecretBytes("managed_keys.aws.secret_access_key", cfg.SecretAccessKey, cfg.SecretAccessKeyFile)
	if err != nil {
		return nil, err
	}
	defer wipeSecret()
	sessionToken, wipeToken, err := managedKeySecretBytes("managed_keys.aws.session_token", cfg.SessionToken, cfg.SessionTokenFile)
	if err != nil {
		return nil, err
	}
	defer wipeToken()

	opts := []awskms.Option{}
	if cfg.Endpoint != "" {
		opts = append(opts, awskms.WithEndpoint(cfg.Endpoint))
	}
	if guard != nil && guard.Enabled() {
		opts = append(opts, awskms.WithHTTPClient(guard.Client(30*time.Second)))
	}
	return awskms.New(cfg.Region, awskms.Credentials{
		AccessKeyID:     cfg.AccessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
	}, opts...), nil
}

func managedKeySecretBytes(name string, inline []byte, file string) ([]byte, func(), error) {
	if len(inline) > 0 && file != "" {
		return nil, func() {}, fmt.Errorf("%s and %s_file are mutually exclusive", name, name)
	}
	if len(inline) > 0 {
		return inline, func() {}, nil
	}
	if file == "" {
		return nil, func() {}, nil
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, func() {}, fmt.Errorf("read %s_file: %w", name, err)
	}
	raw = bytes.TrimSpace(raw)
	return raw, func() { secret.Wipe(raw) }, nil
}
