package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultIsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("Default() must be valid, got: %v", err)
	}
	p := Default().Protocols
	if p.ACME.Enabled || p.EST.Enabled || p.SCEP.Enabled || p.CMP.Enabled || p.TSA.Enabled || p.KMIP.Enabled || p.SPIFFE.Enabled || p.SSH.Enabled {
		t.Fatal("served protocol surfaces must default off until an operator binds a tenant")
	}
	if p.RAKeyFile == "" {
		t.Fatal("protocols.ra_key_file must have a default so SCEP/CMP can persist a stable RA identity when enabled")
	}
	if p.TSACertFile == "" {
		t.Fatal("protocols.tsa_cert_file must have a default so the served TSA can persist a stable certificate when enabled")
	}
	if p.ACMEQuota.MaxNonces <= 0 || p.ACMEQuota.MaxPendingOrders <= 0 || p.ACMEQuota.MaxNewOrdersPerAccount <= 0 || p.ACMEQuota.SourceWindowSeconds <= 0 {
		t.Fatalf("protocols.acme_quota must expose positive safe defaults, got %+v", p.ACMEQuota)
	}
	if Default().ManagedKeys.Enabled {
		t.Fatal("managed-key custody must default off so /api/v1/managed-keys fails closed until configured")
	}
	if Default().ManagedKeys.Provider != ManagedKeyProviderAWS {
		t.Fatalf("managed-key custody default provider = %q, want %q", Default().ManagedKeys.Provider, ManagedKeyProviderAWS)
	}
}

func TestParseOverlaysDefaults(t *testing.T) {
	cfg, err := Parse([]byte(`{"postgres":{"mode":"external","dsn":"postgres://x"}}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Postgres.Mode != "external" || cfg.Postgres.DSN != "postgres://x" {
		t.Errorf("file values not applied: %+v", cfg.Postgres)
	}
	// Fields absent from the file keep their defaults.
	if cfg.Server.Addr != Default().Server.Addr {
		t.Errorf("Server.Addr should keep default, got %q", cfg.Server.Addr)
	}
	if cfg.Log.Format != "json" {
		t.Errorf("Log.Format should keep default json, got %q", cfg.Log.Format)
	}
}

// TestEnvOverridesFile pins the precedence: defaults < file < environment.
func TestEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trstctl.json")
	body := `{"server":{"addr":":1111"},"postgres":{"mode":"external","dsn":"file-dsn"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"TRSTCTL_CONFIG_FILE":                                   path,
		"TRSTCTL_POSTGRES_DSN":                                  "env-dsn",
		"TRSTCTL_LOG_LEVEL":                                     "debug",
		"TRSTCTL_AIRGAP_ENABLED":                                "true",
		"TRSTCTL_AIRGAP_ALLOW_PRIVATE":                          "true",
		"TRSTCTL_AIRGAP_ALLOW_HOSTS":                            "collector.airgap.local",
		"TRSTCTL_AIRGAP_ALLOW_CIDRS":                            "10.0.0.0/8,192.168.0.0/16",
		"TRSTCTL_OUTBOUND_ENV_CREDENTIAL_REFS":                  "env:TRSTCTL_SPLUNK_TOKEN,env:TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY",
		"TRSTCTL_SERVICENOW_INSTANCE_URL":                       "https://example.service-now.com",
		"TRSTCTL_SERVICENOW_TOKEN_REF":                          "env:TRSTCTL_SERVICENOW_TOKEN",
		"TRSTCTL_SERVICENOW_ALLOW_PRIVATE_ENDPOINT":             "true",
		"TRSTCTL_SERVICENOW_PRIVATE_EGRESS_CIDRS":               "10.25.0.0/16,127.0.0.1/32",
		"TRSTCTL_TELEMETRY_INSTANCE_ID_FILE":                    "/var/lib/trstctl/telemetry/instance-id",
		"TRSTCTL_MANAGED_KEYS_ENABLED":                          "true",
		"TRSTCTL_MANAGED_KEYS_PROVIDER":                         "aws",
		"TRSTCTL_MANAGED_KEYS_AWS_REGION":                       "us-east-1",
		"TRSTCTL_MANAGED_KEYS_AWS_ENDPOINT":                     "http://127.0.0.1:4566",
		"TRSTCTL_MANAGED_KEYS_AWS_ACCESS_KEY_ID":                "test",
		"TRSTCTL_MANAGED_KEYS_AWS_SECRET_ACCESS_KEY":            "test-secret",
		"TRSTCTL_PROTOCOLS_RA_KEY_FILE":                         "/var/lib/trstctl/protocol-ra.key",
		"TRSTCTL_PROTOCOLS_TSA_CERT_FILE":                       "/var/lib/trstctl/tsa.crt",
		"TRSTCTL_PROTOCOLS_ACME_MAX_NONCES":                     "17",
		"TRSTCTL_PROTOCOLS_ACME_MAX_PENDING_ORDERS_PER_ACCOUNT": "3",
		"TRSTCTL_PROTOCOLS_ACME_MAX_NEW_ORDERS_PER_ACCOUNT":     "4",
		"TRSTCTL_PROTOCOLS_ACME_SOURCE_WINDOW_SECONDS":          "45",
		"TRSTCTL_PROTOCOLS_SCEP_ENABLED":                        "true",
		"TRSTCTL_PROTOCOLS_SCEP_TENANT_ID":                      "11111111-1111-1111-1111-111111111111",
		"TRSTCTL_PROTOCOLS_TSA_ENABLED":                         "true",
		"TRSTCTL_PROTOCOLS_TSA_TENANT_ID":                       "11111111-1111-1111-1111-111111111111",
		"TRSTCTL_PROTOCOLS_KMIP_ENABLED":                        "true",
		"TRSTCTL_PROTOCOLS_KMIP_TENANT_ID":                      "11111111-1111-1111-1111-111111111111",
		"TRSTCTL_PROTOCOLS_KMIP_ADDR":                           ":5697",
		"TRSTCTL_PROTOCOLS_KMIP_CERT_FILE":                      "/var/lib/trstctl/kmip.crt",
		"TRSTCTL_PROTOCOLS_KMIP_KEY_FILE":                       "/var/lib/trstctl/kmip.key",
		"TRSTCTL_PROTOCOLS_KMIP_CLIENT_CA_FILE":                 "/var/lib/trstctl/kmip-clients.crt",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Postgres.DSN != "env-dsn" {
		t.Errorf("env must override file dsn: got %q", cfg.Postgres.DSN)
	}
	if cfg.Server.Addr != ":1111" {
		t.Errorf("file must override default addr: got %q", cfg.Server.Addr)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("env must override default log level: got %q", cfg.Log.Level)
	}
	if !cfg.AirGap.Enabled || !cfg.AirGap.AllowPrivate || strings.Join(cfg.AirGap.AllowHosts, ",") != "collector.airgap.local" || strings.Join(cfg.AirGap.AllowCIDRs, ",") != "10.0.0.0/8,192.168.0.0/16" {
		t.Errorf("air-gap env overrides not applied: %+v", cfg.AirGap)
	}
	if strings.Join(cfg.OutboundEnvCredentialRefs, ",") != "env:TRSTCTL_SPLUNK_TOKEN,env:TRSTCTL_DISCOVERY_AWS_SECRET_ACCESS_KEY" {
		t.Errorf("outbound env credential ref allowlist env override not applied: %+v", cfg.OutboundEnvCredentialRefs)
	}
	if got := cfg.ITSM.ServiceNow.Bindings; len(got) != 1 || got[0].InstanceURL != "https://example.service-now.com" || got[0].TokenRef != "env:TRSTCTL_SERVICENOW_TOKEN" || !got[0].AllowPrivateEndpoint || strings.Join(got[0].PrivateEgressCIDRs, ",") != "10.25.0.0/16,127.0.0.1/32" {
		t.Errorf("ServiceNow binding env override not applied: %+v", got)
	}
	if cfg.Telemetry.InstanceIDFile != "/var/lib/trstctl/telemetry/instance-id" {
		t.Errorf("telemetry instance id env override not applied: %q", cfg.Telemetry.InstanceIDFile)
	}
	if cfg.Protocols.RAKeyFile != "/var/lib/trstctl/protocol-ra.key" {
		t.Errorf("protocols.ra_key_file env override not applied: got %q", cfg.Protocols.RAKeyFile)
	}
	if cfg.Protocols.TSACertFile != "/var/lib/trstctl/tsa.crt" {
		t.Errorf("protocols.tsa_cert_file env override not applied: got %q", cfg.Protocols.TSACertFile)
	}
	if cfg.Protocols.ACMEQuota.MaxNonces != 17 {
		t.Errorf("protocols.acme_quota.max_nonces env override not applied: got %d", cfg.Protocols.ACMEQuota.MaxNonces)
	}
	if cfg.Protocols.ACMEQuota.MaxPendingOrdersPerAccount != 3 {
		t.Errorf("protocols.acme_quota.max_pending_orders_per_account env override not applied: got %d", cfg.Protocols.ACMEQuota.MaxPendingOrdersPerAccount)
	}
	if cfg.Protocols.ACMEQuota.MaxNewOrdersPerAccount != 4 {
		t.Errorf("protocols.acme_quota.max_new_orders_per_account env override not applied: got %d", cfg.Protocols.ACMEQuota.MaxNewOrdersPerAccount)
	}
	if cfg.Protocols.ACMEQuota.SourceWindowSeconds != 45 {
		t.Errorf("protocols.acme_quota.source_window_seconds env override not applied: got %d", cfg.Protocols.ACMEQuota.SourceWindowSeconds)
	}
	if !cfg.Protocols.SCEP.Enabled || cfg.Protocols.SCEP.TenantID == "" {
		t.Errorf("SCEP env enable+tenant should apply, got %+v", cfg.Protocols.SCEP)
	}
	if !cfg.Protocols.TSA.Enabled || cfg.Protocols.TSA.TenantID == "" {
		t.Errorf("TSA env enable+tenant should apply, got %+v", cfg.Protocols.TSA)
	}
	if !cfg.Protocols.KMIP.Enabled || cfg.Protocols.KMIP.TenantID == "" || cfg.Protocols.KMIP.Addr != ":5697" || cfg.Protocols.KMIP.CertFile == "" || cfg.Protocols.KMIP.KeyFile == "" || cfg.Protocols.KMIP.ClientCAFile == "" {
		t.Errorf("KMIP env enable+tenant+mTLS should apply, got %+v", cfg.Protocols.KMIP)
	}
	if !cfg.ManagedKeys.Enabled || cfg.ManagedKeys.Provider != ManagedKeyProviderAWS || cfg.ManagedKeys.AWS.Region != "us-east-1" || cfg.ManagedKeys.AWS.Endpoint != "http://127.0.0.1:4566" || cfg.ManagedKeys.AWS.AccessKeyID != "test" || string(cfg.ManagedKeys.AWS.SecretAccessKey) != "test-secret" {
		t.Errorf("managed-key AWS env enable+custody config should apply, got %+v", cfg.ManagedKeys)
	}
	if cfg.NATS.Mode != Default().NATS.Mode {
		t.Errorf("untouched NATS.Mode should be default: got %q", cfg.NATS.Mode)
	}
}

func TestManagedKeyPKCS11EnvAndValidation(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_MANAGED_KEYS_ENABLED":                    "true",
		"TRSTCTL_MANAGED_KEYS_PROVIDER":                   "pkcs11",
		"TRSTCTL_MANAGED_KEYS_PKCS11_MODULE_PATH":         "/usr/lib/softhsm/libsofthsm2.so",
		"TRSTCTL_MANAGED_KEYS_PKCS11_TOKEN_LABEL":         "trstctl-prod",
		"TRSTCTL_MANAGED_KEYS_PKCS11_USER_PIN":            "123456",
		"TRSTCTL_MANAGED_KEYS_PKCS11_KEY_LABEL_PREFIX":    "trstctl-ca",
		"TRSTCTL_MANAGED_KEYS_AWS_REGION":                 "",
		"TRSTCTL_MANAGED_KEYS_AWS_ACCESS_KEY_ID":          "",
		"TRSTCTL_MANAGED_KEYS_AWS_SECRET_ACCESS_KEY":      "",
		"TRSTCTL_MANAGED_KEYS_AWS_SECRET_ACCESS_KEY_FILE": "",
		"TRSTCTL_MANAGED_KEYS_AWS_SESSION_TOKEN":          "",
		"TRSTCTL_MANAGED_KEYS_AWS_SESSION_TOKEN_FILE":     "",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load PKCS#11 managed-key config: %v", err)
	}
	if !cfg.ManagedKeys.Enabled || cfg.ManagedKeys.Provider != ManagedKeyProviderPKCS11 {
		t.Fatalf("PKCS#11 managed-key provider not enabled: %+v", cfg.ManagedKeys)
	}
	if got := cfg.ManagedKeys.PKCS11; got.ModulePath != "/usr/lib/softhsm/libsofthsm2.so" || got.TokenLabel != "trstctl-prod" || string(got.UserPIN) != "123456" || got.KeyLabelPrefix != "trstctl-ca" {
		t.Fatalf("PKCS#11 managed-key env config not applied: %+v", got)
	}

	c := Default()
	c.ManagedKeys.Enabled = true
	c.ManagedKeys.Provider = ManagedKeyProviderPKCS11
	c.ManagedKeys.PKCS11.ModulePath = "/usr/lib/softhsm/libsofthsm2.so"
	c.ManagedKeys.PKCS11.TokenLabel = "trstctl-prod"
	c.ManagedKeys.PKCS11.UserPINFile = "/etc/trstctl/pkcs11-pin"
	if err := c.Validate(); err != nil {
		t.Fatalf("valid PKCS#11 managed-key config rejected: %v", err)
	}
}

func TestManagedKeyCloudKMSEnvAndValidation(t *testing.T) {
	azureEnv := map[string]string{
		"TRSTCTL_MANAGED_KEYS_ENABLED":                 "true",
		"TRSTCTL_MANAGED_KEYS_PROVIDER":                "azure-key-vault",
		"TRSTCTL_MANAGED_KEYS_AZURE_VAULT_URL":         "https://trstctl-prod.managedhsm.azure.net",
		"TRSTCTL_MANAGED_KEYS_AZURE_ENDPOINT":          "https://private.azure.local",
		"TRSTCTL_MANAGED_KEYS_AZURE_BEARER_TOKEN":      "azure-token",
		"TRSTCTL_MANAGED_KEYS_AZURE_BEARER_TOKEN_FILE": "",
	}
	cfg, err := Load(func(k string) string { return azureEnv[k] })
	if err != nil {
		t.Fatalf("Load Azure managed-key config: %v", err)
	}
	if !cfg.ManagedKeys.Enabled || cfg.ManagedKeys.Provider != ManagedKeyProviderAzureKeyVault {
		t.Fatalf("Azure managed-key provider not enabled: %+v", cfg.ManagedKeys)
	}
	if got := cfg.ManagedKeys.Azure; got.VaultURL != "https://trstctl-prod.managedhsm.azure.net" || got.Endpoint != "https://private.azure.local" || string(got.BearerToken) != "azure-token" {
		t.Fatalf("Azure managed-key env config not applied: %+v", got)
	}

	gcpEnv := map[string]string{
		"TRSTCTL_MANAGED_KEYS_ENABLED":               "true",
		"TRSTCTL_MANAGED_KEYS_PROVIDER":              "gcp-kms",
		"TRSTCTL_MANAGED_KEYS_GCP_PARENT":            "projects/p/locations/us/keyRings/trstctl",
		"TRSTCTL_MANAGED_KEYS_GCP_ENDPOINT":          "https://cloudkms-private.googleapis.com/v1",
		"TRSTCTL_MANAGED_KEYS_GCP_BEARER_TOKEN":      "gcp-token",
		"TRSTCTL_MANAGED_KEYS_GCP_BEARER_TOKEN_FILE": "",
	}
	cfg, err = Load(func(k string) string { return gcpEnv[k] })
	if err != nil {
		t.Fatalf("Load GCP managed-key config: %v", err)
	}
	if !cfg.ManagedKeys.Enabled || cfg.ManagedKeys.Provider != ManagedKeyProviderGCPKMS {
		t.Fatalf("GCP managed-key provider not enabled: %+v", cfg.ManagedKeys)
	}
	if got := cfg.ManagedKeys.GCP; got.Parent != "projects/p/locations/us/keyRings/trstctl" || got.Endpoint != "https://cloudkms-private.googleapis.com/v1" || string(got.BearerToken) != "gcp-token" {
		t.Fatalf("GCP managed-key env config not applied: %+v", got)
	}

	c := Default()
	c.ManagedKeys.Enabled = true
	c.ManagedKeys.Provider = ManagedKeyProviderAzureKeyVault
	c.ManagedKeys.Azure.VaultURL = "https://trstctl-prod.managedhsm.azure.net"
	c.ManagedKeys.Azure.BearerTokenFile = "/etc/trstctl/azure-kv-token"
	if err := c.Validate(); err != nil {
		t.Fatalf("valid Azure managed-key config rejected: %v", err)
	}

	c = Default()
	c.ManagedKeys.Enabled = true
	c.ManagedKeys.Provider = ManagedKeyProviderGCPKMS
	c.ManagedKeys.GCP.Parent = "projects/p/locations/us/keyRings/trstctl"
	c.ManagedKeys.GCP.BearerTokenFile = "/etc/trstctl/gcp-kms-token"
	if err := c.Validate(); err != nil {
		t.Fatalf("valid GCP managed-key config rejected: %v", err)
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	cases := map[string]func(*Config){
		"postgres mode":        func(c *Config) { c.Postgres.Mode = "weird" },
		"external without dsn": func(c *Config) { c.Postgres.Mode = "external"; c.Postgres.DSN = "" },
		"nats mode":            func(c *Config) { c.NATS.Mode = "weird" },
		"external without url": func(c *Config) { c.NATS.Mode = "external"; c.NATS.URL = "" },
		"external single nats without eval opt-in": func(c *Config) {
			c.NATS.Mode = "external"
			c.NATS.URL = "nats://nats:4222"
			c.NATS.Replicas = 1
		},
		"log level":              func(c *Config) { c.Log.Level = "loud" },
		"log format":             func(c *Config) { c.Log.Format = "binary" },
		"empty addr":             func(c *Config) { c.Server.Addr = "" },
		"negative nats replicas": func(c *Config) { c.NATS.Replicas = -1 },
		"too many nats replicas": func(c *Config) { c.NATS.Replicas = 6 },
		"bad nats sync interval": func(c *Config) { c.NATS.SyncInterval = "soon" },
		"airgap telemetry enabled": func(c *Config) {
			c.AirGap.Enabled = true
			c.Telemetry.Enabled = true
		},
		"airgap cloud ai": func(c *Config) {
			c.AirGap.Enabled = true
			c.AI.Model.Mode = AIModelCloud
			c.AI.Model.Provider = "openai"
			c.AI.Model.Endpoint = "https://api.openai.example/v1/chat/completions"
			c.AI.Model.Name = "model"
			c.AI.Model.AllowEgress = true
		},
		"airgap bad cidr":    func(c *Config) { c.AirGap.AllowCIDRs = []string{"not-a-cidr"} },
		"airgap host is url": func(c *Config) { c.AirGap.AllowHosts = []string{"https://collector.example.com"} },
		"outbound env credential ref missing env prefix": func(c *Config) {
			c.OutboundEnvCredentialRefs = []string{"AWS_SECRET_ACCESS_KEY"}
		},
		"outbound env credential ref empty": func(c *Config) {
			c.OutboundEnvCredentialRefs = []string{"env:"}
		},
		"outbound env credential ref duplicate": func(c *Config) {
			c.OutboundEnvCredentialRefs = []string{"env:TRSTCTL_SPLUNK_TOKEN", "env:TRSTCTL_SPLUNK_TOKEN"}
		},
		"servicenow missing instance": func(c *Config) {
			c.ITSM.ServiceNow.Bindings = []ServiceNowBinding{{TokenRef: "env:TRSTCTL_SERVICENOW_TOKEN"}}
		},
		"servicenow bad token ref": func(c *Config) {
			c.ITSM.ServiceNow.Bindings = []ServiceNowBinding{{InstanceURL: "https://example.service-now.com", TokenRef: "env:"}}
		},
		"servicenow http without private approval": func(c *Config) {
			c.ITSM.ServiceNow.Bindings = []ServiceNowBinding{{InstanceURL: "http://127.0.0.1:8080", TokenRef: "env:TRSTCTL_SERVICENOW_TOKEN"}}
		},
		"servicenow private missing cidr grant": func(c *Config) {
			c.ITSM.ServiceNow.Bindings = []ServiceNowBinding{{InstanceURL: "https://example.service-now.com", TokenRef: "env:TRSTCTL_SERVICENOW_TOKEN", AllowPrivateEndpoint: true}}
		},
		"servicenow private bad cidr grant": func(c *Config) {
			c.ITSM.ServiceNow.Bindings = []ServiceNowBinding{{InstanceURL: "https://example.service-now.com", TokenRef: "env:TRSTCTL_SERVICENOW_TOKEN", AllowPrivateEndpoint: true, PrivateEgressCIDRs: []string{"not-a-cidr"}}}
		},
		"servicenow cidr without private approval": func(c *Config) {
			c.ITSM.ServiceNow.Bindings = []ServiceNowBinding{{InstanceURL: "https://example.service-now.com", TokenRef: "env:TRSTCTL_SERVICENOW_TOKEN", PrivateEgressCIDRs: []string{"10.0.0.0/8"}}}
		},
		"telemetry missing instance id file": func(c *Config) {
			c.Telemetry.Enabled = true
			c.Telemetry.InstanceIDFile = ""
		},
		"zero acme quota":     func(c *Config) { c.Protocols.ACMEQuota.MaxNonces = 0 },
		"negative acme quota": func(c *Config) { c.Protocols.ACMEQuota.MaxNewOrdersPerSource = -1 },
		"managed keys missing region": func(c *Config) {
			c.ManagedKeys.Enabled = true
			c.ManagedKeys.AWS.AccessKeyID = "test"
			c.ManagedKeys.AWS.SecretAccessKey = []byte("test")
		},
		"managed keys missing secret": func(c *Config) {
			c.ManagedKeys.Enabled = true
			c.ManagedKeys.AWS.Region = "us-east-1"
			c.ManagedKeys.AWS.AccessKeyID = "test"
		},
		"managed keys bad endpoint": func(c *Config) {
			c.ManagedKeys.Enabled = true
			c.ManagedKeys.AWS.Region = "us-east-1"
			c.ManagedKeys.AWS.AccessKeyID = "test"
			c.ManagedKeys.AWS.SecretAccessKey = []byte("test")
			c.ManagedKeys.AWS.Endpoint = "127.0.0.1:4566"
		},
		"managed keys unknown provider": func(c *Config) {
			c.ManagedKeys.Enabled = true
			c.ManagedKeys.Provider = "runtime-plugin-engine"
			c.ManagedKeys.AWS.Region = "us-east-1"
			c.ManagedKeys.AWS.AccessKeyID = "test"
			c.ManagedKeys.AWS.SecretAccessKey = []byte("test")
		},
		"azure managed keys missing vault": func(c *Config) {
			c.ManagedKeys.Enabled = true
			c.ManagedKeys.Provider = ManagedKeyProviderAzureKeyVault
			c.ManagedKeys.Azure.BearerToken = []byte("token")
		},
		"azure managed keys missing token": func(c *Config) {
			c.ManagedKeys.Enabled = true
			c.ManagedKeys.Provider = ManagedKeyProviderAzureKeyVault
			c.ManagedKeys.Azure.VaultURL = "https://trstctl-prod.managedhsm.azure.net"
		},
		"azure managed keys bad endpoint": func(c *Config) {
			c.ManagedKeys.Enabled = true
			c.ManagedKeys.Provider = ManagedKeyProviderAzureKeyVault
			c.ManagedKeys.Azure.VaultURL = "https://trstctl-prod.managedhsm.azure.net"
			c.ManagedKeys.Azure.BearerToken = []byte("token")
			c.ManagedKeys.Azure.Endpoint = "private.azure.local"
		},
		"gcp managed keys missing parent": func(c *Config) {
			c.ManagedKeys.Enabled = true
			c.ManagedKeys.Provider = ManagedKeyProviderGCPKMS
			c.ManagedKeys.GCP.BearerToken = []byte("token")
		},
		"gcp managed keys missing token": func(c *Config) {
			c.ManagedKeys.Enabled = true
			c.ManagedKeys.Provider = ManagedKeyProviderGCPKMS
			c.ManagedKeys.GCP.Parent = "projects/p/locations/us/keyRings/trstctl"
		},
		"gcp managed keys bad endpoint": func(c *Config) {
			c.ManagedKeys.Enabled = true
			c.ManagedKeys.Provider = ManagedKeyProviderGCPKMS
			c.ManagedKeys.GCP.Parent = "projects/p/locations/us/keyRings/trstctl"
			c.ManagedKeys.GCP.BearerToken = []byte("token")
			c.ManagedKeys.GCP.Endpoint = "cloudkms-private.googleapis.com/v1"
		},
		"pkcs11 managed keys missing module": func(c *Config) {
			c.ManagedKeys.Enabled = true
			c.ManagedKeys.Provider = ManagedKeyProviderPKCS11
			c.ManagedKeys.PKCS11.TokenLabel = "trstctl-prod"
			c.ManagedKeys.PKCS11.UserPIN = []byte("123456")
		},
		"pkcs11 managed keys missing token": func(c *Config) {
			c.ManagedKeys.Enabled = true
			c.ManagedKeys.Provider = ManagedKeyProviderPKCS11
			c.ManagedKeys.PKCS11.ModulePath = "/usr/lib/softhsm/libsofthsm2.so"
			c.ManagedKeys.PKCS11.UserPIN = []byte("123456")
		},
		"pkcs11 managed keys missing pin": func(c *Config) {
			c.ManagedKeys.Enabled = true
			c.ManagedKeys.Provider = ManagedKeyProviderPKCS11
			c.ManagedKeys.PKCS11.ModulePath = "/usr/lib/softhsm/libsofthsm2.so"
			c.ManagedKeys.PKCS11.TokenLabel = "trstctl-prod"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := Default()
			mutate(c)
			if err := c.Validate(); err == nil {
				t.Errorf("expected a validation error for %q", name)
			}
		})
	}
}

func TestExternalModesValidWithConnection(t *testing.T) {
	c := Default()
	c.Postgres.Mode = "external"
	c.Postgres.DSN = "postgres://u:p@host:5432/db"
	c.NATS.Mode = "external"
	c.NATS.URL = "nats://host:4222"
	c.Signer.AllowCoResidentAuthorizer = false
	c.Signer.AuthTokenCommand = "/usr/local/bin/trstctl-sign-approve"
	if err := c.Validate(); err != nil {
		t.Fatalf("external config with connection strings should validate: %v", err)
	}
}

func TestEnabledProtocolsRequireTenantBinding(t *testing.T) {
	c := Default()
	c.Protocols.ACME.Enabled = true
	c.Protocols.EST.Enabled = true
	c.Protocols.SCEP.Enabled = true
	c.Protocols.CMP.Enabled = true
	c.Protocols.TSA.Enabled = true
	c.Protocols.KMIP.Enabled = true
	err := c.Validate()
	if err == nil {
		t.Fatal("tenantless enabled enrollment protocols must fail config validation")
	}
	msg := err.Error()
	for _, want := range []string{
		"protocols.acme.tenant_id is required",
		"protocols.est.tenant_id is required",
		"protocols.scep.tenant_id is required",
		"protocols.cmp.tenant_id is required",
		"protocols.tsa.tenant_id is required",
		"protocols.kmip.tenant_id is required",
		"AN-1",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("validation error missing %q: %v", want, err)
		}
	}
}

func TestEnabledProtocolsValidateWithExplicitTenant(t *testing.T) {
	c := Default()
	for _, toggle := range []*ProtocolToggle{&c.Protocols.ACME, &c.Protocols.EST, &c.Protocols.SCEP, &c.Protocols.CMP, &c.Protocols.TSA} {
		toggle.Enabled = true
		toggle.TenantID = "11111111-1111-1111-1111-111111111111"
	}
	c.Protocols.KMIP.Enabled = true
	c.Protocols.KMIP.TenantID = "11111111-1111-1111-1111-111111111111"
	c.Protocols.KMIP.CertFile = "/var/lib/trstctl/kmip.crt"
	c.Protocols.KMIP.KeyFile = "/var/lib/trstctl/kmip.key"
	c.Protocols.KMIP.ClientCAFile = "/var/lib/trstctl/kmip-clients.crt"
	if err := c.Validate(); err != nil {
		t.Fatalf("enabled protocols with explicit tenants should validate: %v", err)
	}
}

func TestKMIPRequiresMTLSMaterial(t *testing.T) {
	c := Default()
	c.Protocols.KMIP.Enabled = true
	c.Protocols.KMIP.TenantID = "11111111-1111-1111-1111-111111111111"
	err := c.Validate()
	if err == nil {
		t.Fatal("KMIP without mTLS material must fail validation")
	}
	for _, want := range []string{
		"protocols.kmip.cert_file is required",
		"protocols.kmip.key_file is required",
		"protocols.kmip.client_ca_file is required",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("validation error missing %q: %v", want, err)
		}
	}
}

func TestSCEPCMPRequireStableRAKeyFile(t *testing.T) {
	c := Default()
	c.Protocols.SCEP.Enabled = true
	c.Protocols.SCEP.TenantID = "11111111-1111-1111-1111-111111111111"
	c.Protocols.CMP.Enabled = true
	c.Protocols.CMP.TenantID = "11111111-1111-1111-1111-111111111111"
	c.Protocols.RAKeyFile = ""
	err := c.Validate()
	if err == nil {
		t.Fatal("SCEP/CMP without protocols.ra_key_file must fail validation")
	}
	if !strings.Contains(err.Error(), "protocols.ra_key_file is required") {
		t.Fatalf("validation error should name protocols.ra_key_file, got %v", err)
	}
}

func TestTSARequiresStableCertificateFile(t *testing.T) {
	c := Default()
	c.Protocols.TSA.Enabled = true
	c.Protocols.TSA.TenantID = "11111111-1111-1111-1111-111111111111"
	c.Protocols.TSACertFile = ""
	err := c.Validate()
	if err == nil {
		t.Fatal("TSA without protocols.tsa_cert_file must fail validation")
	}
	if !strings.Contains(err.Error(), "protocols.tsa_cert_file is required") {
		t.Fatalf("validation error should name protocols.tsa_cert_file, got %v", err)
	}
}

func TestProtocolTenantFallbackIsOnlyForServerComposition(t *testing.T) {
	p := Protocols{
		ACME:        ProtocolToggle{Enabled: true},
		EST:         ProtocolToggle{Enabled: true},
		SCEP:        ProtocolToggle{Enabled: true},
		CMP:         ProtocolToggle{Enabled: true},
		TSA:         ProtocolToggle{Enabled: true},
		RAKeyFile:   "data/protocols/ra-transport.key",
		TSACertFile: "data/protocols/tsa.crt",
		KMIP: KMIPProtocol{
			Enabled:      true,
			CertFile:     "/var/lib/trstctl/kmip.crt",
			KeyFile:      "/var/lib/trstctl/kmip.key",
			ClientCAFile: "/var/lib/trstctl/kmip-clients.crt",
		},
		SSH:    ProtocolToggle{Enabled: true},
		SPIFFE: SPIFFEProtocol{Enabled: true, TrustDomain: "example.org"},
	}
	if errs := p.ValidateTenantBindings(""); len(errs) == 0 {
		t.Fatal("tenantless enabled protocols should fail without an explicit fallback")
	}
	if errs := p.ValidateTenantBindings("11111111-1111-1111-1111-111111111111"); len(errs) != 0 {
		t.Fatalf("server composition fallback should satisfy tenant binding: %v", errors.Join(errs...))
	}
}

// TestTelemetryOffByDefault pins the privacy-first default: telemetry is
// disabled unless explicitly enabled (S7.5 acceptance).
func TestTelemetryOffByDefault(t *testing.T) {
	if Default().Telemetry.Enabled {
		t.Fatal("telemetry must be OFF by default")
	}
	// An empty environment keeps it off.
	cfg, err := Load(func(string) string { return "" })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Telemetry.Enabled {
		t.Error("telemetry must stay off with no opt-in")
	}
}

// TestTelemetryOptInViaEnv: the operator opts in explicitly through the
// environment, and the endpoint/interval defaults are present.
func TestTelemetryOptInViaEnv(t *testing.T) {
	env := map[string]string{"TRSTCTL_TELEMETRY_ENABLED": "true"}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Telemetry.Enabled {
		t.Error("TRSTCTL_TELEMETRY_ENABLED=true must enable telemetry")
	}
	if cfg.Telemetry.Endpoint == "" {
		t.Error("an enabled telemetry config must have a default endpoint")
	}
	if cfg.Telemetry.InstanceIDFile == "" {
		t.Error("an enabled telemetry config must have a default instance-id file")
	}
	if d, err := cfg.Telemetry.IntervalDuration(); err != nil || d <= 0 {
		t.Errorf("telemetry interval must default to a positive duration, got %v (%v)", d, err)
	}
}

// TestTelemetryValidation: when enabled, telemetry needs a valid https endpoint
// and a positive interval.
func TestTelemetryValidation(t *testing.T) {
	cases := map[string]func(*Config){
		"enabled without endpoint": func(c *Config) { c.Telemetry.Enabled = true; c.Telemetry.Endpoint = "" },
		"enabled non-https":        func(c *Config) { c.Telemetry.Enabled = true; c.Telemetry.Endpoint = "http://t.example/v1" },
		"enabled bad interval":     func(c *Config) { c.Telemetry.Enabled = true; c.Telemetry.Interval = "soon" },
		"enabled zero interval":    func(c *Config) { c.Telemetry.Enabled = true; c.Telemetry.Interval = "0s" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := Default()
			mutate(c)
			if err := c.Validate(); err == nil {
				t.Errorf("expected a validation error for %q", name)
			}
		})
	}

	// Disabled telemetry imposes no endpoint/interval requirements.
	c := Default()
	c.Telemetry.Enabled = false
	c.Telemetry.Endpoint = ""
	c.Telemetry.Interval = ""
	if err := c.Validate(); err != nil {
		t.Errorf("disabled telemetry must not require an endpoint: %v", err)
	}
}

func TestOTLPExportOffByDefault(t *testing.T) {
	if Default().OTLP.Enabled {
		t.Fatal("otlp export must be OFF by default")
	}
	cfg, err := Load(func(string) string { return "" })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.OTLP.Enabled {
		t.Error("otlp export must stay off with no opt-in")
	}
}

func TestOTLPExportOptInViaEnv(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_OTLP_ENABLED":      "true",
		"TRSTCTL_OTLP_ENDPOINT":     "http://otel-collector:4318",
		"TRSTCTL_OTLP_INSECURE":     "true",
		"TRSTCTL_OTLP_BEARER_TOKEN": "collector-token",
		"TRSTCTL_OTLP_TIMEOUT":      "2s",
		"TRSTCTL_OTLP_QUEUE_SIZE":   "128",
		"TRSTCTL_OTLP_SERVICE_NAME": "trstctl-prod",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.OTLP.Enabled || cfg.OTLP.Endpoint != "http://otel-collector:4318" || !cfg.OTLP.Insecure {
		t.Fatalf("otlp env overlay did not apply: %+v", cfg.OTLP)
	}
	if string(cfg.OTLP.Token) != "collector-token" || cfg.OTLP.QueueSize != 128 || cfg.OTLP.ServiceName != "trstctl-prod" {
		t.Fatalf("otlp secret/queue/service env overlay did not apply: %+v", cfg.OTLP)
	}
	if d, err := cfg.OTLP.TimeoutDuration(); err != nil || d != 2*time.Second {
		t.Fatalf("otlp timeout = %v (%v), want 2s", d, err)
	}
}

func TestOTLPExportValidation(t *testing.T) {
	cases := map[string]func(*Config){
		"enabled without endpoint": func(c *Config) { c.OTLP.Enabled = true; c.OTLP.Endpoint = "" },
		"enabled bad endpoint":     func(c *Config) { c.OTLP.Enabled = true; c.OTLP.Endpoint = "collector:4318" },
		"enabled plain http":       func(c *Config) { c.OTLP.Enabled = true; c.OTLP.Endpoint = "http://collector:4318" },
		"enabled bad timeout": func(c *Config) {
			c.OTLP.Enabled = true
			c.OTLP.Endpoint = "https://collector:4318"
			c.OTLP.Timeout = "soon"
		},
		"enabled zero timeout": func(c *Config) {
			c.OTLP.Enabled = true
			c.OTLP.Endpoint = "https://collector:4318"
			c.OTLP.Timeout = "0s"
		},
		"negative queue": func(c *Config) {
			c.OTLP.Enabled = true
			c.OTLP.Endpoint = "https://collector:4318"
			c.OTLP.QueueSize = -1
		},
		"token and file": func(c *Config) {
			c.OTLP.Enabled = true
			c.OTLP.Endpoint = "https://collector:4318"
			c.OTLP.Token = []byte("tok")
			c.OTLP.TokenFile = "/run/secrets/otlp-token"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := Default()
			mutate(c)
			if err := c.Validate(); err == nil {
				t.Errorf("expected a validation error for %q", name)
			}
		})
	}

	c := Default()
	c.OTLP.Enabled = true
	c.OTLP.Endpoint = "http://collector:4318"
	c.OTLP.Insecure = true
	if err := c.Validate(); err != nil {
		t.Errorf("explicit insecure OTLP collector should validate: %v", err)
	}
}

// TestEmbeddedEventLogFsyncDefaultIsBounded pins RESIL-001: the default
// (embedded) event log is configured to fsync on a tight bounded cadence, NOT
// nats-server's ~2-minute default — so a single-node power loss bounds data loss
// to ~1s. The pre-fix tree left SyncInterval empty (the ~2-minute default applied),
// so this fails before the fix.
func TestEmbeddedEventLogFsyncDefaultIsBounded(t *testing.T) {
	d, err := Default().NATS.SyncIntervalDuration()
	if err != nil {
		t.Fatalf("default sync interval must parse: %v", err)
	}
	if d <= 0 {
		t.Fatalf("embedded event log must have a bounded fsync cadence by default, got %v (the unbounded nats-server ~2m default)", d)
	}
	if d > 5*time.Second {
		t.Errorf("default embedded fsync cadence %v is too loose for a single-node RPO target", d)
	}
	if DefaultEmbeddedSyncInterval <= 0 || DefaultEmbeddedSyncInterval > 5*time.Second {
		t.Errorf("DefaultEmbeddedSyncInterval = %v, want a small positive bound", DefaultEmbeddedSyncInterval)
	}
}

// TestEventStreamReplicasConfigurable pins SPINE-004: the event-stream replication
// factor is a config knob, surfaced through config + env, with a non-trivial default
// in external (clustered) mode.
func TestEventStreamReplicasConfigurable(t *testing.T) {
	if DefaultExternalReplicas < 3 {
		t.Errorf("DefaultExternalReplicas = %d, want >= 3 for HA", DefaultExternalReplicas)
	}
	// Config knob round-trips through the env overlay.
	env := map[string]string{
		"TRSTCTL_NATS_REPLICAS":             "5",
		"TRSTCTL_NATS_ALLOW_SINGLE_REPLICA": "true",
		"TRSTCTL_NATS_SYNC_INTERVAL":        "250ms",
		"TRSTCTL_NATS_SYNC_ALWAYS":          "true",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.NATS.Replicas != 5 {
		t.Errorf("NATS.Replicas = %d, want 5 from env", cfg.NATS.Replicas)
	}
	if !cfg.NATS.AllowSingleReplica {
		t.Error("NATS.AllowSingleReplica must be settable via env")
	}
	if cfg.NATS.SyncInterval != "250ms" {
		t.Errorf("NATS.SyncInterval = %q, want 250ms from env", cfg.NATS.SyncInterval)
	}
	if !cfg.NATS.SyncAlways {
		t.Error("NATS.SyncAlways must be settable via env")
	}
}

func TestFederationEnvOverridesAndValidation(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_FEDERATION_ENABLED":       "true",
		"TRSTCTL_FEDERATION_CLUSTER_ID":    "us-west-passive",
		"TRSTCTL_FEDERATION_REGION":        "us-west-2",
		"TRSTCTL_FEDERATION_PEER_ID":       "us-east-primary",
		"TRSTCTL_FEDERATION_PEER_REGION":   "us-east-1",
		"TRSTCTL_FEDERATION_PEER_NATS_URL": "nats://nats.us-east.example:4222",
		"TRSTCTL_FEDERATION_INTERVAL":      "2s",
		"TRSTCTL_FEDERATION_RPO":           "5s",
		"TRSTCTL_FEDERATION_RTO":           "30s",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load federation env: %v", err)
	}
	if !cfg.Federation.Enabled || cfg.Federation.ClusterID != "us-west-passive" || cfg.Federation.Region != "us-west-2" {
		t.Fatalf("federation env did not apply: %+v", cfg.Federation)
	}
	if len(cfg.Federation.Peers) != 1 || cfg.Federation.Peers[0].ID != "us-east-primary" || cfg.Federation.Peers[0].NATSURL == "" {
		t.Fatalf("federation peer env did not apply: %+v", cfg.Federation.Peers)
	}
	if d, err := cfg.Federation.IntervalDuration(); err != nil || d != 2*time.Second {
		t.Fatalf("federation interval = %v (%v), want 2s", d, err)
	}

	bad := Default()
	bad.Federation.Enabled = true
	bad.Federation.ClusterID = "us-west-passive"
	bad.Federation.Peers = []FederationPeer{{ID: "us-east-primary"}}
	if err := bad.Validate(); err == nil {
		t.Fatal("federation enabled without peer nats_url should fail validation")
	}
}

func TestFullBackupEncryptionConfigurable(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_BACKUP_ENCRYPTION_KEY_FILE": "/secure/backup.key",
		"TRSTCTL_BACKUP_ALLOW_UNENCRYPTED":   "true",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Backup.EncryptionKeyFile != "/secure/backup.key" {
		t.Errorf("Backup.EncryptionKeyFile = %q", cfg.Backup.EncryptionKeyFile)
	}
	if !cfg.Backup.AllowUnencrypted {
		t.Error("Backup.AllowUnencrypted must be settable via env")
	}
}
