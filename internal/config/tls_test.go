package config

import (
	"strings"
	"testing"
)

// TestTLSOnByDefault: the control plane serves TLS by default — plaintext is an
// explicit opt-in, not the fallback (B4).
func TestTLSOnByDefault(t *testing.T) {
	if got := Default().Server.TLS.Mode; got != TLSInternal {
		t.Errorf("default server.tls.mode = %q, want %q (TLS must be on by default)", got, TLSInternal)
	}
	if err := Default().Validate(); err != nil {
		t.Fatalf("Default() must be valid, got: %v", err)
	}
}

// TestTLSValidateFailFast: TLS configuration is rejected before the server boots
// when it is internally inconsistent, consistent with the rest of Validate().
func TestTLSValidateFailFast(t *testing.T) {
	cases := map[string]struct {
		tls     TLS
		wantErr string
	}{
		"unknown mode":          {TLS{Mode: "off"}, "server.tls.mode"},
		"file without cert/key": {TLS{Mode: TLSFile}, "server.tls.cert_file"},
		"file without key":      {TLS{Mode: TLSFile, CertFile: "/x/cert.pem"}, "server.tls.key_file"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := Default()
			c.Server.TLS = tc.tls
			err := c.Validate()
			if err == nil {
				t.Fatalf("Validate accepted an invalid TLS config: %+v", tc.tls)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}

	// The valid combinations pass.
	for _, ok := range []TLS{
		{Mode: TLSInternal},
		{Mode: TLSDisabled},
		{Mode: TLSFile, CertFile: "/x/cert.pem", KeyFile: "/x/key.pem"},
	} {
		c := Default()
		c.Server.TLS = ok
		if err := c.Validate(); err != nil {
			t.Errorf("valid TLS config %+v rejected: %v", ok, err)
		}
	}
}

// TestTLSEnvOverrides: the TLS mode and cert/key paths come from the environment.
func TestTLSEnvOverrides(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_SERVER_TLS_MODE":      "file",
		"TRSTCTL_SERVER_TLS_CERT_FILE": "/etc/trstctl/tls.crt",
		"TRSTCTL_SERVER_TLS_KEY_FILE":  "/etc/trstctl/tls.key",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.TLS.Mode != TLSFile || cfg.Server.TLS.CertFile != "/etc/trstctl/tls.crt" || cfg.Server.TLS.KeyFile != "/etc/trstctl/tls.key" {
		t.Errorf("TLS env not applied: %+v", cfg.Server.TLS)
	}
}
