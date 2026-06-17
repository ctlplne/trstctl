package config_test

import (
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// TestSignerDefaultsToChild: the signer is a supervised child by default, with a
// sealed key store and a persisted CA cert so a restart preserves the CA (R3.2).
func TestSignerDefaultsToChild(t *testing.T) {
	c := config.Default()
	if c.Signer.Mode != config.SignerChild {
		t.Errorf("signer.mode default = %q, want %q", c.Signer.Mode, config.SignerChild)
	}
	if c.Signer.KeyStoreDir == "" {
		t.Error("signer.key_store_dir should have a default (sealed key persistence)")
	}
	if c.Signer.AuthSecretFile == "" {
		t.Error("signer.auth_secret_file should have a default (SIGNER-001 content authorization)")
	}
	if c.CA.CertFile == "" {
		t.Error("ca.cert_file should have a default (persisted issuing-CA cert)")
	}
}

// TestSignerExternalRequiresSocket: an external signer needs a socket; a bogus
// mode fails fast.
func TestSignerExternalRequiresSocket(t *testing.T) {
	base := map[string]string{
		"TRSTCTL_POSTGRES_MODE": "external",
		"TRSTCTL_POSTGRES_DSN":  "postgres://u:p@h:5432/db?sslmode=require",
		"TRSTCTL_NATS_MODE":     "external",
		"TRSTCTL_NATS_URL":      "nats://h:4222",
	}

	if _, err := config.Load(envFunc(base, map[string]string{"TRSTCTL_SIGNER_MODE": "external"})); err == nil {
		t.Error("external signer without a socket should fail validation")
	}
	if _, err := config.Load(envFunc(base, map[string]string{
		"TRSTCTL_SIGNER_MODE":             "external",
		"TRSTCTL_SIGNER_SOCKET":           "/run/trstctl/signer.sock",
		"TRSTCTL_SIGNER_AUTH_SECRET_FILE": "/run/trstctl/sign-auth.bin",
	})); err != nil {
		t.Errorf("external signer with a socket should validate: %v", err)
	}
	noAuth := config.Default()
	noAuth.Postgres.Mode = "external"
	noAuth.Postgres.DSN = "postgres://u:p@h:5432/db?sslmode=require"
	noAuth.NATS.Mode = "external"
	noAuth.NATS.URL = "nats://h:4222"
	noAuth.Signer.Mode = "external"
	noAuth.Signer.Socket = "/run/trstctl/signer.sock"
	noAuth.Signer.AuthSecretFile = ""
	if err := noAuth.Validate(); err == nil {
		t.Error("external signer without signer.auth_secret_file should fail validation")
	}
	if _, err := config.Load(envFunc(base, map[string]string{"TRSTCTL_SIGNER_MODE": "bogus"})); err == nil {
		t.Error("an invalid signer.mode should fail validation")
	}
}

// TestSignerExternalMTLSValidation (SIGNER-005): the cross-node mTLS signer
// transport is selected by signer.mtls_address; it requires the full mTLS material
// and is mutually exclusive with a UDS socket. A complete block validates and is
// reported as mTLS-enabled.
func TestSignerExternalMTLSValidation(t *testing.T) {
	base := map[string]string{
		"TRSTCTL_POSTGRES_MODE": "external",
		"TRSTCTL_POSTGRES_DSN":  "postgres://u:p@h:5432/db?sslmode=require",
		"TRSTCTL_NATS_MODE":     "external",
		"TRSTCTL_NATS_URL":      "nats://h:4222",
	}
	full := map[string]string{
		"TRSTCTL_SIGNER_MODE":              "external",
		"TRSTCTL_SIGNER_MTLS_ADDRESS":      "signer.trstctl.svc:9443",
		"TRSTCTL_SIGNER_MTLS_SERVER_NAME":  "signer.trstctl.svc",
		"TRSTCTL_SIGNER_MTLS_CERT_FILE":    "/etc/cp/tls.crt",
		"TRSTCTL_SIGNER_MTLS_KEY_FILE":     "/etc/cp/tls.key",
		"TRSTCTL_SIGNER_MTLS_PEER_CA_FILE": "/etc/cp/signer-ca.pem",
		"TRSTCTL_SIGNER_MTLS_PEER_PIN":     "abc123",
		"TRSTCTL_SIGNER_AUTH_SECRET_FILE":  "/etc/trstctl/signer-auth/sign-auth.bin",
	}

	// A complete mTLS block validates and reports MTLSEnabled.
	c, err := config.Load(envFunc(base, full))
	if err != nil {
		t.Fatalf("external signer with a complete mTLS block should validate: %v", err)
	}
	if !c.Signer.MTLSEnabled() {
		t.Error("Signer.MTLSEnabled() should be true when mtls_address is set")
	}

	// Missing any one piece fails closed.
	for _, drop := range []string{
		"TRSTCTL_SIGNER_MTLS_SERVER_NAME",
		"TRSTCTL_SIGNER_MTLS_CERT_FILE",
		"TRSTCTL_SIGNER_MTLS_KEY_FILE",
		"TRSTCTL_SIGNER_MTLS_PEER_CA_FILE",
		"TRSTCTL_SIGNER_MTLS_PEER_PIN",
	} {
		partial := map[string]string{}
		for k, v := range full {
			if k != drop {
				partial[k] = v
			}
		}
		if _, err := config.Load(envFunc(base, partial)); err == nil {
			t.Errorf("external signer mTLS without %s should fail validation (fail closed)", drop)
		}
	}

	// Socket AND mtls_address together is rejected (one listener).
	both := map[string]string{"TRSTCTL_SIGNER_SOCKET": "/run/trstctl/signer.sock"}
	for k, v := range full {
		both[k] = v
	}
	if _, err := config.Load(envFunc(base, both)); err == nil {
		t.Error("external signer with BOTH a socket and an mtls_address should fail validation")
	}
}
