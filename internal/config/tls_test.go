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

// TestServerTLS is the WIRE-101 aggregate guard: the served control-plane transport
// defaults to TLS, plaintext is a loopback-only local-development exception, and
// operator-provided TLS cannot boot without both certificate and key files.
func TestServerTLS(t *testing.T) {
	t.Run("default is TLS", func(t *testing.T) {
		c := Default()
		if got := c.Server.TLS.Mode; got != TLSInternal {
			t.Fatalf("default server.tls.mode = %q, want %q", got, TLSInternal)
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("default TLS config should validate: %v", err)
		}
	})

	t.Run("disabled needs explicit dev override", func(t *testing.T) {
		c := Default()
		c.Server.Addr = "127.0.0.1:8080"
		c.Server.TLS = TLS{Mode: TLSDisabled}
		err := c.Validate()
		if err == nil {
			t.Fatal("Validate accepted disabled TLS without the dev override")
		}
		if !strings.Contains(err.Error(), "TRSTCTL_DEV_ALLOW_PLAINTEXT") {
			t.Fatalf("error = %v, want dev override requirement", err)
		}
	})

	t.Run("disabled dev mode is loopback only", func(t *testing.T) {
		for _, addr := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080"} {
			c := Default()
			c.Server.Addr = addr
			c.Server.TLS = TLS{Mode: TLSDisabled, AllowPlaintextDev: true}
			if err := c.Validate(); err != nil {
				t.Fatalf("loopback disabled TLS config %q should validate: %v", addr, err)
			}
		}

		for _, addr := range []string{":8080", "0.0.0.0:8080", "[::]:8080", "192.0.2.10:8080"} {
			c := Default()
			c.Server.Addr = addr
			c.Server.TLS = TLS{Mode: TLSDisabled, AllowPlaintextDev: true}
			err := c.Validate()
			if err == nil {
				t.Fatalf("Validate accepted disabled TLS on non-loopback addr %q", addr)
			}
			if !strings.Contains(err.Error(), "loopback") {
				t.Fatalf("error = %v, want loopback requirement", err)
			}
		}
	})

	t.Run("file mode needs cert and key", func(t *testing.T) {
		c := Default()
		c.Server.TLS = TLS{Mode: TLSFile}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "server.tls.cert_file") {
			t.Fatalf("file TLS without cert/key error = %v, want cert_file requirement", err)
		}

		c = Default()
		c.Server.TLS = TLS{Mode: TLSFile, CertFile: "/x/cert.pem"}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "server.tls.key_file") {
			t.Fatalf("file TLS without key error = %v, want key_file requirement", err)
		}

		c = Default()
		c.Server.TLS = TLS{Mode: TLSFile, CertFile: "/x/cert.pem", KeyFile: "/x/key.pem"}
		if err := c.Validate(); err != nil {
			t.Fatalf("complete file TLS config should validate: %v", err)
		}
	})
}

// TestTLSValidateFailFast: TLS configuration is rejected before the server boots
// when it is internally inconsistent, consistent with the rest of Validate().
func TestTLSValidateFailFast(t *testing.T) {
	cases := map[string]struct {
		tls     TLS
		wantErr string
	}{
		"unknown mode":                   {TLS{Mode: "off"}, "server.tls.mode"},
		"file without cert/key":          {TLS{Mode: TLSFile}, "server.tls.cert_file"},
		"file without key":               {TLS{Mode: TLSFile, CertFile: "/x/cert.pem"}, "server.tls.key_file"},
		"disabled without dev override":  {TLS{Mode: TLSDisabled}, "TRSTCTL_DEV_ALLOW_PLAINTEXT"},
		"disabled with default wildcard": {TLS{Mode: TLSDisabled, AllowPlaintextDev: true}, "loopback"},
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
		{Mode: TLSFile, CertFile: "/x/cert.pem", KeyFile: "/x/key.pem"},
	} {
		c := Default()
		c.Server.TLS = ok
		if err := c.Validate(); err != nil {
			t.Errorf("valid TLS config %+v rejected: %v", ok, err)
		}
	}
}

func TestTLSDisabledRequiresDevOverride(t *testing.T) {
	c := Default()
	c.Server.Addr = "127.0.0.1:8080"
	c.Server.TLS.Mode = TLSDisabled
	err := c.Validate()
	if err == nil {
		t.Fatal("Validate accepted disabled TLS without TRSTCTL_DEV_ALLOW_PLAINTEXT")
	}
	if !strings.Contains(err.Error(), "TRSTCTL_DEV_ALLOW_PLAINTEXT") {
		t.Fatalf("error = %v, want dev override requirement", err)
	}
}

func TestTLSDisabledLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080"} {
		t.Run("allow "+addr, func(t *testing.T) {
			c := Default()
			c.Server.Addr = addr
			c.Server.TLS = TLS{Mode: TLSDisabled, AllowPlaintextDev: true}
			if err := c.Validate(); err != nil {
				t.Fatalf("Validate rejected loopback disabled TLS config: %v", err)
			}
		})
	}

	for _, addr := range []string{":8080", "0.0.0.0:8080", "[::]:8080", "192.0.2.10:8080"} {
		t.Run("reject "+addr, func(t *testing.T) {
			c := Default()
			c.Server.Addr = addr
			c.Server.TLS = TLS{Mode: TLSDisabled, AllowPlaintextDev: true}
			err := c.Validate()
			if err == nil {
				t.Fatalf("Validate accepted disabled TLS on non-loopback addr %q", addr)
			}
			if !strings.Contains(err.Error(), "loopback") {
				t.Fatalf("error = %v, want loopback requirement", err)
			}
		})
	}
}

// TestTLSEnvOverrides: the TLS mode and cert/key paths come from the environment.
func TestTLSEnvOverrides(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_SERVER_TLS_MODE":      "file",
		"TRSTCTL_SERVER_TLS_CERT_FILE": "/etc/trstctl/tls.crt",
		"TRSTCTL_SERVER_TLS_KEY_FILE":  "/etc/trstctl/tls.key",
		"TRSTCTL_DEV_ALLOW_PLAINTEXT":  "true",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.TLS.Mode != TLSFile || cfg.Server.TLS.CertFile != "/etc/trstctl/tls.crt" || cfg.Server.TLS.KeyFile != "/etc/trstctl/tls.key" {
		t.Errorf("TLS env not applied: %+v", cfg.Server.TLS)
	}
	if !cfg.Server.TLS.AllowPlaintextDev {
		t.Error("TRSTCTL_DEV_ALLOW_PLAINTEXT was not applied")
	}
}
