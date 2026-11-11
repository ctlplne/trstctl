// SPDX-License-Identifier: BUSL-1.1

package wrapadapter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"trstctl.com/trstctl/internal/cloudauth"
	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/kms/awskms"
	"trstctl.com/trstctl/internal/kms/azurekv"
	"trstctl.com/trstctl/internal/kms/gcpkms"
	"trstctl.com/trstctl/internal/kms/kmsconn"
	"trstctl.com/trstctl/internal/kms/pkcs11"
	"trstctl.com/trstctl/internal/netsec"
)

// awsProvider wraps with KMS Encrypt under a symmetric key. Decrypt names the
// same key, so a blob another key produced is refused by KMS.
type awsProvider struct{ backend *awskms.Backend }

// awsSourceStatic is the default credential source: an access key ID with
// its secret file (A200-L1 adds the cloudauth.AWSSource* chain sources).
const awsSourceStatic = "static"

func newAWS(ctx context.Context, cfg AWSConfig, keyRef string, getenv func(string) string) (provider, error) {
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		region = arnRegion(keyRef)
	}
	if region == "" {
		return nil, usagef("aws: region is required unless the key reference is a key ARN")
	}
	source := strings.ToLower(strings.TrimSpace(cfg.CredentialSource))
	if source == "" {
		source = awsSourceStatic
	}
	webIdentityFields := strings.TrimSpace(cfg.RoleARN) != "" || strings.TrimSpace(cfg.WebIdentityTokenFile) != "" ||
		strings.TrimSpace(cfg.RoleSessionName) != "" || strings.TrimSpace(cfg.STSEndpoint) != ""
	var creds awskms.Credentials
	switch source {
	case awsSourceStatic:
		if webIdentityFields {
			return nil, usagef("aws: role_arn, web_identity_token_file, role_session_name and sts_endpoint need credential_source web_identity or default_chain")
		}
		if strings.TrimSpace(cfg.AccessKeyID) == "" {
			return nil, usagef("aws: access_key_id is required, or set credential_source to web_identity, container, instance_metadata or default_chain")
		}
		if err := kmsconn.ValidateEndpoints("aws", cfg.AllowInsecureLoopback, cfg.Endpoint); err != nil {
			return nil, usageError{err}
		}
		secretKey, wipeSecret, err := kmsconn.CredentialFile("aws secret access key", cfg.SecretAccessKeyFile, true)
		if err != nil {
			return nil, usageError{err}
		}
		defer wipeSecret()
		session, wipeSession, err := kmsconn.CredentialFile("aws session token", cfg.SessionTokenFile, false)
		if err != nil {
			return nil, usageError{err}
		}
		defer wipeSession()
		creds = awskms.Credentials{AccessKeyID: cfg.AccessKeyID, SecretAccessKey: secretKey, SessionToken: session}
	case cloudauth.AWSSourceWebIdentity, cloudauth.AWSSourceContainer, cloudauth.AWSSourceInstanceMetadata, cloudauth.AWSSourceDefaultChain:
		if cfg.AccessKeyID != "" || cfg.SecretAccessKeyFile != "" || cfg.SessionTokenFile != "" {
			return nil, usagef("aws: credential_source %s reads no access_key_id, secret_access_key_file or session_token_file", source)
		}
		if webIdentityFields && source != cloudauth.AWSSourceWebIdentity && source != cloudauth.AWSSourceDefaultChain {
			return nil, usagef("aws: role_arn, web_identity_token_file, role_session_name and sts_endpoint need credential_source web_identity or default_chain")
		}
		if err := kmsconn.ValidateEndpoints("aws", cfg.AllowInsecureLoopback, cfg.Endpoint, cfg.STSEndpoint); err != nil {
			return nil, usageError{err}
		}
		material, err := resolveAWSChain(ctx, cfg, source, region, getenv)
		if err != nil {
			return nil, err
		}
		defer secret.Wipe(material.Primary)
		defer secret.Wipe(material.Secondary)
		creds = awskms.Credentials{AccessKeyID: material.Identifier, SecretAccessKey: material.Primary, SessionToken: material.Secondary}
	default:
		return nil, usagef("aws: credential_source must be static, web_identity, container, instance_metadata or default_chain")
	}
	client, err := kmsconn.EgressClient(cfg.PrivateEgressCIDRs, cfg.Endpoint, cfg.AllowInsecureLoopback)
	if err != nil {
		return nil, usageError{fmt.Errorf("aws egress: %w", err)}
	}
	opts := []awskms.Option{awskms.WithHTTPClient(client)}
	if cfg.Endpoint != "" {
		opts = append(opts, awskms.WithEndpoint(cfg.Endpoint))
	}
	backend, err := awskms.NewSecure(region, creds, opts...)
	if err != nil {
		return nil, err
	}
	return &awsProvider{backend: backend}, nil
}

// resolveAWSChain reads temporary credentials from the configured source
// (A200-L1). STS is reached through the same egress rules as KMS; the
// metadata endpoints only through netsec's metadata client, which dials
// nothing but AWS's link-local credential addresses (or a loopback agent).
func resolveAWSChain(ctx context.Context, cfg AWSConfig, source, region string, getenv func(string) string) (cloudauth.Material, error) {
	stsEndpoint := strings.TrimSpace(cfg.STSEndpoint)
	if stsEndpoint == "" {
		stsEndpoint = cloudauth.AWSRegionalSTSEndpoint(region)
	}
	stsClient, err := kmsconn.EgressClient(cfg.PrivateEgressCIDRs, stsEndpoint, cfg.AllowInsecureLoopback)
	if err != nil {
		return cloudauth.Material{}, usageError{fmt.Errorf("aws sts egress: %w", err)}
	}
	material, _, err := cloudauth.AWSCredentialChain{
		Source:               source,
		Getenv:               getenv,
		RoleARN:              cfg.RoleARN,
		WebIdentityTokenFile: cfg.WebIdentityTokenFile,
		RoleSessionName:      cfg.RoleSessionName,
		STSEndpoint:          stsEndpoint,
		STSDoer:              stsClient,
		MetadataDoer: func(endpoint string) (cloudhttp.Doer, error) {
			return netsec.CloudMetadataClient(endpoint, 0)
		},
	}.Resolve(ctx)
	if err != nil {
		return cloudauth.Material{}, fmt.Errorf("aws credentials: %w", err)
	}
	return material, nil
}

// arnRegion is the region field of a KMS key or alias ARN
// (arn:<partition>:kms:<region>:<account>:...), or "".
func arnRegion(keyRef string) string {
	parts := strings.SplitN(keyRef, ":", 6)
	if len(parts) == 6 && parts[0] == "arn" && parts[2] == "kms" {
		return parts[3]
	}
	return ""
}

func awsContext() map[string]string { return map[string]string{"trstctl:purpose": Purpose} }

func (*awsProvider) code() byte { return codeAWS }

func (p *awsProvider) wrap(ctx context.Context, keyRef string, dataKey []byte) ([]byte, []byte, error) {
	wrapped, err := p.backend.EncryptDataKey(ctx, keyRef, dataKey, awsContext())
	return nil, wrapped, err
}

func (p *awsProvider) unwrap(ctx context.Context, keyRef string, meta, wrapped []byte) ([]byte, error) {
	if len(meta) != 0 {
		return nil, errors.New("unexpected wrap metadata")
	}
	return p.backend.DecryptDataKey(ctx, keyRef, wrapped, awsContext())
}

func (p *awsProvider) close() { p.backend.Destroy() }

// gcpProvider wraps with Cloud KMS encrypt under a CryptoKey; decrypt names
// the same CryptoKey and the service picks the version that encrypted.
type gcpProvider struct{ backend *gcpkms.Backend }

func newGCP(cfg GCPConfig) (provider, error) {
	if err := kmsconn.ValidateEndpoints("gcp", cfg.AllowInsecureLoopback, cfg.Endpoint); err != nil {
		return nil, usageError{err}
	}
	token, wipe, err := kmsconn.CredentialFile("gcp bearer token", cfg.BearerTokenFile, true)
	if err != nil {
		return nil, usageError{err}
	}
	defer wipe()
	client, err := kmsconn.EgressClient(cfg.PrivateEgressCIDRs, cfg.Endpoint, cfg.AllowInsecureLoopback)
	if err != nil {
		return nil, usageError{fmt.Errorf("gcp egress: %w", err)}
	}
	opts := []gcpkms.Option{gcpkms.WithHTTPClient(client)}
	if cfg.Endpoint != "" {
		opts = append(opts, gcpkms.WithEndpoint(cfg.Endpoint))
	}
	backend, err := gcpkms.NewSecure("", gcpkms.Credentials{BearerToken: token}, opts...)
	if err != nil {
		return nil, err
	}
	return &gcpProvider{backend: backend}, nil
}

func (*gcpProvider) code() byte { return codeGCP }

func (p *gcpProvider) wrap(ctx context.Context, keyRef string, dataKey []byte) ([]byte, []byte, error) {
	wrapped, err := p.backend.EncryptDataKey(ctx, keyRef, dataKey, []byte(Purpose))
	return nil, wrapped, err
}

func (p *gcpProvider) unwrap(ctx context.Context, keyRef string, meta, wrapped []byte) ([]byte, error) {
	if len(meta) != 0 {
		return nil, errors.New("unexpected wrap metadata")
	}
	return p.backend.DecryptDataKey(ctx, keyRef, wrapped, []byte(Purpose))
}

func (p *gcpProvider) close() { p.backend.Destroy() }

// azureProvider wraps with Key Vault wrapkey. The key reference is the key's
// identifier, https://<vault>/keys/<name>[/<version>]; without a version the
// current one wraps. The frame records the algorithm and the version that
// wrapped, so a key rotated to a new version still unwraps older data keys,
// and only versions of the referenced key are ever used.
type azureProvider struct {
	backend   *azurekv.Backend
	name      string
	version   string
	algorithm string
}

func newAzure(cfg AzureConfig, keyRef string) (provider, error) {
	vault, name, version, err := parseAzureKeyRef(keyRef)
	if err != nil {
		return nil, usageError{err}
	}
	algorithm := strings.TrimSpace(cfg.Algorithm)
	if algorithm == "" {
		algorithm = azurekv.WrapRSAOAEP256
	}
	if !azurekv.ValidWrapAlgorithm(algorithm) {
		return nil, usagef("azure: algorithm %q is not RSA-OAEP-256, A256KW or CKM_AES_KEY_WRAP_PAD", algorithm)
	}
	if err := kmsconn.ValidateEndpoints("azure", cfg.AllowInsecureLoopback, vault, cfg.Endpoint); err != nil {
		return nil, usageError{err}
	}
	token, wipe, err := kmsconn.CredentialFile("azure bearer token", cfg.BearerTokenFile, true)
	if err != nil {
		return nil, usageError{err}
	}
	defer wipe()
	endpoint := cfg.Endpoint
	if strings.TrimSpace(endpoint) == "" {
		endpoint = vault
	}
	client, err := kmsconn.EgressClient(cfg.PrivateEgressCIDRs, endpoint, cfg.AllowInsecureLoopback)
	if err != nil {
		return nil, usageError{fmt.Errorf("azure egress: %w", err)}
	}
	opts := []azurekv.Option{azurekv.WithHTTPClient(client)}
	if cfg.Endpoint != "" {
		opts = append(opts, azurekv.WithEndpoint(cfg.Endpoint))
	}
	backend, err := azurekv.NewSecure(vault, azurekv.Credentials{BearerToken: token}, opts...)
	if err != nil {
		return nil, err
	}
	return &azureProvider{backend: backend, name: name, version: version, algorithm: algorithm}, nil
}

// parseAzureKeyRef splits https://<vault>/keys/<name>[/<version>].
func parseAzureKeyRef(keyRef string) (vault, name, version string, err error) {
	u, err := url.Parse(keyRef)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", "", "", errors.New("azure: the key reference must be a key identifier, https://<vault>/keys/<name>[/<version>]")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "keys" || parts[1] == "" {
		return "", "", "", errors.New("azure: the key reference must be a key identifier, https://<vault>/keys/<name>[/<version>]")
	}
	if len(parts) == 3 {
		version = parts[2]
	}
	return u.Scheme + "://" + u.Host, parts[1], version, nil
}

func (*azureProvider) code() byte { return codeAzure }

func (p *azureProvider) wrap(ctx context.Context, _ string, dataKey []byte) ([]byte, []byte, error) {
	version, wrapped, err := p.backend.WrapDataKey(ctx, p.name, p.version, p.algorithm, dataKey)
	if err != nil {
		return nil, nil, err
	}
	return []byte(p.algorithm + " " + version), wrapped, nil
}

func (p *azureProvider) unwrap(ctx context.Context, _ string, meta, wrapped []byte) ([]byte, error) {
	algorithm, version, ok := bytes.Cut(meta, []byte(" "))
	if !ok || !azurekv.ValidWrapAlgorithm(string(algorithm)) || len(version) == 0 {
		return nil, errors.New("the wrapped data key's Key Vault metadata is malformed")
	}
	return p.backend.UnwrapDataKey(ctx, p.name, string(version), string(algorithm), wrapped)
}

func (p *azureProvider) close() { p.backend.Destroy() }

// pkcs11Provider seals the data key with AES-256-GCM under the token AES key
// whose label is the key reference; the key never leaves the token.
type pkcs11Provider struct {
	session pkcs11.Session
	keys    pkcs11.SecretKeySession
}

func newPKCS11(cfg PKCS11Config) (provider, error) {
	if strings.TrimSpace(cfg.ModulePath) == "" || strings.TrimSpace(cfg.TokenLabel) == "" {
		return nil, usagef("pkcs11: module_path and token_label are required")
	}
	pin, wipe, err := kmsconn.CredentialFile("pkcs11 user PIN", cfg.UserPINFile, true)
	if err != nil {
		return nil, usageError{err}
	}
	defer wipe()
	session, err := pkcs11.OpenModuleSession(pkcs11.ModuleConfig{
		ModulePath: cfg.ModulePath, TokenLabel: cfg.TokenLabel, UserPIN: pin,
	})
	if err != nil {
		return nil, fmt.Errorf("%w (the PKCS#11 adapter is the cgo build in the HSM signer image)", err)
	}
	keys, ok := session.(pkcs11.SecretKeySession)
	if !ok {
		_ = session.Close()
		return nil, errors.New("pkcs11: the session cannot seal under an AES key")
	}
	return &pkcs11Provider{session: session, keys: keys}, nil
}

func (*pkcs11Provider) code() byte { return codePKCS11 }

func (p *pkcs11Provider) wrap(_ context.Context, keyRef string, dataKey []byte) ([]byte, []byte, error) {
	sealed, err := p.keys.SealWithKey(keyRef, dataKey, []byte(Purpose))
	return nil, sealed, err
}

func (p *pkcs11Provider) unwrap(_ context.Context, keyRef string, meta, wrapped []byte) ([]byte, error) {
	if len(meta) != 0 {
		return nil, errors.New("unexpected wrap metadata")
	}
	return p.keys.OpenWithKey(keyRef, wrapped, []byte(Purpose))
}

func (p *pkcs11Provider) close() { _ = p.session.Close() }
