// SPDX-License-Identifier: MPL-2.0

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
	if !c.Signer.AllowCoResidentAuthorizer {
		t.Error("single-node eval defaults should keep the co-resident authorizer explicitly marked as eval-only")
	}
	if c.CA.CertFile == "" {
		t.Error("ca.cert_file should have a default (persisted issuing-CA cert)")
	}
}

func TestCAPublicCertificateMirrorEnv(t *testing.T) {
	const publicPath = "/public-trust/issuing-ca.crt"
	c, err := config.Load(func(key string) string {
		if key == "TRSTCTL_CA_PUBLIC_CERT_FILE" {
			return publicPath
		}
		return ""
	})
	if err != nil {
		t.Fatalf("load CA public certificate mirror env: %v", err)
	}
	if c.CA.PublicCertFile != publicPath {
		t.Fatalf("ca.public_cert_file = %q, want %q", c.CA.PublicCertFile, publicPath)
	}
}

// TestSignerExternalRequiresSocket: an external signer needs a socket; a bogus
// mode fails fast.
func TestSignerExternalRequiresSocket(t *testing.T) {
	base := map[string]string{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		"TRSTCTL_POSTGRES_MODE":                       "external",
		"TRSTCTL_POSTGRES_DSN":                        "postgres://u:p@h:5432/db?sslmode=require",
		"TRSTCTL_NATS_MODE":                           "external",
		"TRSTCTL_NATS_URL":                            "nats://h:4222",
		"TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND":           "/usr/local/bin/trstctl-sign-approve",
		"TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER": "false",
	}

	if _, err := config.Load(envFunc(base, map[string]string{"TRSTCTL_SIGNER_MODE": "external"})); err == nil {
		t.Error("external signer without a socket should fail validation")
	}
	if _, err := config.Load(envFunc(base, map[string]string{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		"TRSTCTL_SIGNER_MODE":             "external",
		"TRSTCTL_SIGNER_SOCKET":           "/run/trstctl/signer.sock",
		"TRSTCTL_SIGNER_AUTH_SECRET_FILE": "/run/trstctl/sign-auth.bin",
	})); err != nil {
		t.Errorf("external signer with a socket should validate: %v", err)
	}
	if _, err := config.Load(envFunc(base, map[string]string{"TRSTCTL_SIGNER_MODE": "bogus"})); err == nil {
		t.Error("an invalid signer.mode should fail validation")
	}
}

func TestSignerCoResidentAuthorizerIsEvalOnly(t *testing.T) {
	prod := config.Default()
	prod.Postgres.Mode = config.PostgresExternal
	prod.Postgres.DSN = "postgres://u:p@h:5432/db?sslmode=require"
	prod.NATS.Mode = config.NATSExternal
	prod.NATS.URL = "nats://h:4222"
	prod.NATS.Replicas = config.DefaultExternalReplicas
	prod.NATS.AllowSingleReplica = false
	prod.Signer.Mode = config.SignerExternal
	prod.Signer.Socket = "/run/trstctl/signer.sock"
	prod.Signer.AuthSecretFile = ""
	prod.Signer.AllowCoResidentAuthorizer = true
	if err := prod.Validate(); err == nil {
		t.Error("production-like external NATS must reject a co-resident signer authorizer")
	}

	prod.Signer.AllowCoResidentAuthorizer = false
	if err := prod.Validate(); err == nil {
		t.Error("production-like external NATS must require an independent signer auth token command")
	}

	prod.Signer.AuthTokenCommand = "/usr/local/bin/trstctl-sign-approve"
	if err := prod.Validate(); err != nil {
		t.Errorf("production-like signer with an external token command should validate: %v", err)
	}
}

func TestSignerNonLinuxDevHardeningOverrideIsExplicit(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_SIGNER_ALLOW_INSECURE_DEV_NONLINUX": "true",
	}
	c, err := config.Load(envFunc(nil, env))
	if err != nil {
		t.Fatalf("load signer non-Linux dev override: %v", err)
	}
	if !c.Signer.AllowInsecureDevNonLinux {
		t.Fatal("TRSTCTL_SIGNER_ALLOW_INSECURE_DEV_NONLINUX was not applied")
	}
	if c.Signer.AllowInsecureDevNonLinux && c.Signer.Mode != config.SignerChild {
		t.Fatal("the non-Linux hardening override is only intended for the child signer development path")
	}
}

// TestSignerExternalMTLSValidation (SIGNER-005): the cross-node mTLS signer
// transport is selected by signer.mtls_address; it requires the full mTLS material
// and is mutually exclusive with a UDS socket. A complete block validates and is
// reported as mTLS-enabled.
func TestSignerExternalMTLSValidation(t *testing.T) {
	base := map[string]string{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		"TRSTCTL_POSTGRES_MODE":                       "external",
		"TRSTCTL_POSTGRES_DSN":                        "postgres://u:p@h:5432/db?sslmode=require",
		"TRSTCTL_NATS_MODE":                           "external",
		"TRSTCTL_NATS_URL":                            "nats://h:4222",
		"TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND":           "/usr/local/bin/trstctl-sign-approve",
		"TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER": "false",
	}
	full := map[string]string{ // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
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
