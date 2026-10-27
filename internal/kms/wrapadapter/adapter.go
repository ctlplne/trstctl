// SPDX-License-Identifier: BUSL-1.1

// Package wrapadapter is trstctl-kms-wrap, the signer key store's KMS/HSM wrap
// adapter. trstctl-signer, started with --kms-provider, --kms-key-ref and
// --kms-wrap-command, runs it without a shell as
//
//	trstctl-kms-wrap wrap|unwrap <provider> <keyRef>
//
// with a data key, or a wrapped one, on stdin and reads the result from stdout
// (internal/crypto/kmswrap). The data key is wrapped under a key that never
// leaves AWS KMS, Google Cloud KMS, Azure Key Vault or a PKCS#11 HSM, so the
// signer holds no key-encryption key and links no cloud SDK. Provider
// settings and credential files come from the JSON file named by --config or
// TRSTCTL_KMS_WRAP_CONFIG.
package wrapadapter

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"trstctl.com/trstctl/internal/crypto/secret"
)

// ConfigEnv names the adapter's configuration file when --config is absent.
const ConfigEnv = "TRSTCTL_KMS_WRAP_CONFIG"

// Exit codes.
const (
	ExitOK     = 0
	ExitFailed = 1
	ExitUsage  = 2
)

const (
	maxConfigBytes = 1 << 20
	// maxInput bounds stdin: a data key to wrap, or a wrapped one with its
	// header (an RSA-4096 block and a Key Vault version are well inside it).
	maxInput = 16 << 10
)

// frameMagic starts every wrapped data key: the adapter's format version.
var frameMagic = []byte("TKW1")

// Provider codes in the frame, so a wrapped data key names the provider kind
// that wrapped it and is refused early by another.
const (
	codeAWS    byte = 'A'
	codeGCP    byte = 'G'
	codeAzure  byte = 'Z'
	codePKCS11 byte = 'P'
)

// Purpose binds what this adapter wraps: AWS encryption context, Cloud KMS and
// PKCS#11 associated data. A data key wrapped for another use under the same
// key does not unwrap here.
const Purpose = "trstctl.kms-wrap.signer-keystore.v1"

// Config is the adapter's JSON configuration: one block per provider kind, of
// which the provider the signer names must be configured (Azure and PKCS#11
// need theirs; AWS needs credentials; GCP needs a token). Credential values
// are always file references.
type Config struct {
	AWS    AWSConfig    `json:"aws"`
	GCP    GCPConfig    `json:"gcp"`
	Azure  AzureConfig  `json:"azure"`
	PKCS11 PKCS11Config `json:"pkcs11"`
}

// AWSConfig reaches AWS KMS. Region may be left out when the key reference is
// a key ARN, which names it.
type AWSConfig struct {
	Region                string   `json:"region,omitempty"`
	Endpoint              string   `json:"endpoint,omitempty"`
	AllowInsecureLoopback bool     `json:"allow_insecure_loopback,omitempty"`
	AccessKeyID           string   `json:"access_key_id,omitempty"`
	SecretAccessKeyFile   string   `json:"secret_access_key_file,omitempty"`
	SessionTokenFile      string   `json:"session_token_file,omitempty"`
	PrivateEgressCIDRs    []string `json:"private_egress_cidrs,omitempty"`
}

// GCPConfig reaches Google Cloud KMS with an OAuth access token the operator
// keeps fresh in the file (a workload-identity or service-account token).
type GCPConfig struct {
	Endpoint              string   `json:"endpoint,omitempty"`
	AllowInsecureLoopback bool     `json:"allow_insecure_loopback,omitempty"`
	BearerTokenFile       string   `json:"bearer_token_file,omitempty"`
	PrivateEgressCIDRs    []string `json:"private_egress_cidrs,omitempty"`
}

// AzureConfig reaches Azure Key Vault or Managed HSM with an access token for
// https://vault.azure.net kept fresh in the file. Algorithm is the wrap
// algorithm: RSA-OAEP-256 (the default) for an RSA key, A256KW or
// CKM_AES_KEY_WRAP_PAD for a Managed HSM AES key. Endpoint overrides where
// requests go (a private endpoint); the key reference still names the vault.
type AzureConfig struct {
	Endpoint              string   `json:"endpoint,omitempty"`
	AllowInsecureLoopback bool     `json:"allow_insecure_loopback,omitempty"`
	BearerTokenFile       string   `json:"bearer_token_file,omitempty"`
	Algorithm             string   `json:"algorithm,omitempty"`
	PrivateEgressCIDRs    []string `json:"private_egress_cidrs,omitempty"`
}

// PKCS11Config opens the HSM token whose AES key, named by the key reference
// (its CKA_LABEL), wraps the data keys. It needs the cgo build of the adapter.
type PKCS11Config struct {
	ModulePath  string `json:"module_path,omitempty"`
	TokenLabel  string `json:"token_label,omitempty"`
	UserPINFile string `json:"user_pin_file,omitempty"`
}

// provider wraps and unwraps one data key under one key reference.
type provider interface {
	code() byte
	wrap(ctx context.Context, keyRef string, dataKey []byte) (meta, wrapped []byte, err error)
	unwrap(ctx context.Context, keyRef string, meta, wrapped []byte) ([]byte, error)
	close()
}

// usageError is a malformed invocation or configuration.
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func usagef(format string, args ...any) error {
	return usageError{fmt.Errorf(format, args...)}
}

// Run is the adapter's main. args are the arguments after the program name. It
// returns the process exit code and writes only the result to stdout.
func Run(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	out, release, err := run(ctx, args, getenv, stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "trstctl-kms-wrap: %v\n", err)
		var usage usageError
		if errors.As(err, &usage) {
			return ExitUsage
		}
		return ExitFailed
	}
	defer release()
	if _, err := stdout.Write(out); err != nil {
		_, _ = fmt.Fprintf(stderr, "trstctl-kms-wrap: write the result: %v\n", err)
		return ExitFailed
	}
	return ExitOK
}

func run(ctx context.Context, args []string, getenv func(string) string, stdin io.Reader) ([]byte, func(), error) {
	configPath, operation, providerName, keyRef, err := parseArgs(args)
	if err != nil {
		return nil, nil, err
	}
	if configPath == "" && getenv != nil {
		configPath = getenv(ConfigEnv)
	}
	if configPath == "" {
		return nil, nil, usagef("no configuration: pass --config or set %s", ConfigEnv)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, nil, usageError{err}
	}
	input, err := readInput(stdin)
	if err != nil {
		return nil, nil, err
	}
	defer input.Destroy()
	p, err := newProvider(cfg, providerName, keyRef)
	if err != nil {
		return nil, nil, err
	}
	defer p.close()
	if operation == "wrap" {
		meta, wrapped, err := p.wrap(ctx, keyRef, input.Bytes())
		if err != nil {
			return nil, nil, fmt.Errorf("wrap under %s: %w", providerName, err)
		}
		framed, err := frame(p.code(), meta, wrapped)
		return framed, func() {}, err
	}
	code, meta, wrapped, err := unframe(input.Bytes())
	if err != nil {
		return nil, nil, err
	}
	if code != p.code() {
		return nil, nil, fmt.Errorf("the wrapped data key is not from %s", providerName)
	}
	dataKey, err := p.unwrap(ctx, keyRef, meta, wrapped)
	if err != nil {
		return nil, nil, fmt.Errorf("unwrap under %s: %w", providerName, err)
	}
	// The data key leaves only through stdout; until then it is held locked.
	locked, err := secret.NewFrom(dataKey)
	secret.Wipe(dataKey)
	if err != nil {
		return nil, nil, fmt.Errorf("lock the data key: %w", err)
	}
	return locked.Bytes(), locked.Destroy, nil
}

// readInput reads stdin, at most maxInput bytes, into locked memory.
func readInput(stdin io.Reader) (*secret.Buffer, error) {
	raw, err := secret.ReadBounded(stdin, maxInput+1)
	if err != nil {
		secret.Wipe(raw)
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	defer secret.Wipe(raw)
	if len(raw) == 0 || len(raw) > maxInput {
		return nil, usagef("stdin must carry 1 to %d bytes", maxInput)
	}
	locked, err := secret.NewFrom(raw)
	if err != nil {
		return nil, fmt.Errorf("lock stdin: %w", err)
	}
	return locked, nil
}

// parseArgs reads [--config FILE] wrap|unwrap PROVIDER KEYREF.
func parseArgs(args []string) (configPath, operation, providerName, keyRef string, err error) {
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--config" || arg == "-config":
			if i+1 >= len(args) || args[i+1] == "" {
				return "", "", "", "", usagef("--config needs a file")
			}
			i++
			configPath = args[i]
		case strings.HasPrefix(arg, "--config="):
			configPath = strings.TrimPrefix(arg, "--config=")
		case strings.HasPrefix(arg, "-") && len(positional) == 0:
			return "", "", "", "", usagef("unknown flag %q; usage: trstctl-kms-wrap [--config FILE] wrap|unwrap PROVIDER KEYREF", arg)
		default:
			positional = append(positional, arg)
		}
	}
	if len(positional) != 3 {
		return "", "", "", "", usagef("usage: trstctl-kms-wrap [--config FILE] wrap|unwrap PROVIDER KEYREF")
	}
	operation, providerName, keyRef = positional[0], positional[1], strings.TrimSpace(positional[2])
	if operation != "wrap" && operation != "unwrap" {
		return "", "", "", "", usagef("operation %q is neither wrap nor unwrap", operation)
	}
	if keyRef == "" {
		return "", "", "", "", usagef("the key reference is empty")
	}
	return configPath, operation, providerName, keyRef, nil
}

// LoadConfig reads the adapter configuration strictly: one JSON document, no
// unknown fields (an inline credential is one), at most 1 MiB.
func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-named adapter configuration (CWE-22)
	if err != nil {
		return Config{}, fmt.Errorf("open configuration: %w", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}
	if len(raw) > maxConfigBytes {
		return Config{}, fmt.Errorf("configuration exceeds %d bytes", maxConfigBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("configuration must be a single JSON object")
	}
	return cfg, nil
}

// newProvider builds the client for the provider the signer names.
func newProvider(cfg Config, name, keyRef string) (provider, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "awskms", "aws", "aws-kms":
		return newAWS(cfg.AWS, keyRef)
	case "gcpkms", "gcp", "gcp-kms":
		return newGCP(cfg.GCP)
	case "azurekv", "azure", "azure-key-vault":
		return newAzure(cfg.Azure, keyRef)
	case "pkcs11":
		return newPKCS11(cfg.PKCS11)
	default:
		return nil, usagef("unsupported provider %q; use awskms, gcpkms, azurekv or pkcs11", name)
	}
}

// frame is magic || provider code || meta length (uint16) || meta || wrapped.
func frame(code byte, meta, wrapped []byte) ([]byte, error) {
	if len(meta) > 0xffff {
		return nil, errors.New("wrap metadata is too long")
	}
	out := make([]byte, 0, len(frameMagic)+3+len(meta)+len(wrapped))
	out = append(out, frameMagic...)
	out = append(out, code)
	out = binary.BigEndian.AppendUint16(out, uint16(len(meta))) // #nosec G115 -- bounded by the check above (CWE-190)
	out = append(out, meta...)
	return append(out, wrapped...), nil
}

func unframe(in []byte) (code byte, meta, wrapped []byte, err error) {
	header := len(frameMagic) + 3
	if len(in) <= header || !bytes.Equal(in[:len(frameMagic)], frameMagic) {
		return 0, nil, nil, errors.New("the input is not a data key this adapter wrapped")
	}
	code = in[len(frameMagic)]
	metaLen := int(binary.BigEndian.Uint16(in[len(frameMagic)+1 : header]))
	if len(in) <= header+metaLen {
		return 0, nil, nil, errors.New("the wrapped data key is truncated")
	}
	return code, in[header : header+metaLen], in[header+metaLen:], nil
}
