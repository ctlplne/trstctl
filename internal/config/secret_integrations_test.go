// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/redisacl"
)

func TestValidateSecretIntegrationsAcceptsEveryBuiltIn(t *testing.T) {
	const (
		tenant = "11111111-1111-1111-1111-111111111111"
		ref    = "file:/var/lib/trstctl/fixtures/credential"
	)
	role := []string{"reader"}
	cfg := SecretIntegrationsConfig{
		DynamicProviders: []DynamicSecretProviderConfig{
			{TenantID: tenant, ID: "pg", Type: "postgresql", AdminDSNRef: ref, AllowedRoles: role},
			{TenantID: tenant, ID: "mysql", Type: "mysql", AdminDSNRef: ref, Database: "app", Addr: "mysql.internal:3306", AccountHost: "10.4.0.12", AllowedRoles: role},
			{TenantID: tenant, ID: "mongo", Type: "mongodb", AdminDSNRef: ref, Database: "app", AllowedRoles: role},
			{TenantID: tenant, ID: "aws", Type: "aws-iam", Endpoint: "https://sts.example.test", Region: "us-east-1", AccessKeyID: "AKID", SecretAccessRef: ref, AllowedRoles: role, RoleBindings: map[string]string{"reader": "arn:aws:iam::123456789012:role/trstctl-reader"}, MaxTTL: "1h"},
			{TenantID: tenant, ID: "sts", Type: "aws-sts", Endpoint: "https://sts.example.test", Region: "us-east-1", AccessKeyID: "AKID", SecretAccessRef: ref, AllowedRoles: role, RoleBindings: map[string]string{"reader": "arn:aws:iam::123456789012:role/trstctl-reader"}, MaxTTL: "1h"},
			{TenantID: tenant, ID: "gcp", Type: "gcp-iam", Endpoint: "https://iam.example.test", Project: "project", ServiceAccount: "issuer@example.test", BearerTokenRef: ref, AllowedRoles: role},
			{TenantID: tenant, ID: "azure", Type: "azure-entra", Endpoint: "https://graph.example.test", ApplicationObject: "object", ApplicationClient: "client", AzureTenant: "tenant", BearerTokenRef: ref, AllowedRoles: role},
			{TenantID: tenant, ID: "k8s", Type: "kubernetes", Endpoint: "https://kubernetes.example.test", Namespace: "default", KubernetesAudience: "https://kubernetes.example.test", BearerTokenRef: ref, AllowedRoles: role, RoleBindings: map[string]string{"reader": "Role/secret-reader"}},
			{TenantID: tenant, ID: "redis", Type: "redis", Addr: "redis.internal:6379", PasswordRef: ref, RedisTLSServerName: "redis.internal", AllowedRoles: role,
				RedisACLRoles: map[string]redisacl.Role{"reader": {KeyPrefixes: []string{"app:"}, Commands: []string{"get"}}}},
			{TenantID: tenant, ID: "ldap", Type: "ldap", Addr: "ldap.internal:636", BindDN: "cn=admin,dc=example,dc=test", PasswordRef: ref, UsersDN: "ou=leases,dc=example,dc=test", AllowedRoles: role, RoleBindings: map[string]string{"reader": "cn=readers,ou=groups,dc=example,dc=test"}},
			{TenantID: tenant, ID: "totp", Type: "totp", SeedRef: ref, AllowedRoles: role, MaxTTL: "30s"},
		},
		SyncTargets: []SecretSyncTargetConfig{
			{TenantID: tenant, ID: "aws-sm", Type: "aws-secrets-manager", Endpoint: "https://secretsmanager.example.test", Region: "us-east-1", AccessKeyID: "AKID", SecretAccessRef: ref},
			{TenantID: tenant, ID: "gcp-sm", Type: "gcp-secret-manager", Endpoint: "https://secretmanager.example.test", Project: "project", TokenRef: ref},
			{TenantID: tenant, ID: "azure-kv", Type: "azure-key-vault", Endpoint: "https://vault.example.test", TokenRef: ref},
			{TenantID: tenant, ID: "github", Type: "github-actions", Endpoint: "https://api.github.example.test", Owner: "owner", Repo: "repo", TokenRef: ref},
			{TenantID: tenant, ID: "gitlab", Type: "gitlab-ci", Endpoint: "https://gitlab.example.test", ProjectID: "42", TokenRef: ref},
			{TenantID: tenant, ID: "vercel", Type: "vercel", Endpoint: "https://vercel.example.test", ProjectID: "project", TokenRef: ref},
			{TenantID: tenant, ID: "generic", Type: "generic-ci-json", Endpoint: "https://ci.example.test", Provider: "build", TokenRef: ref},
			{TenantID: tenant, ID: "k8s-secret", Type: "kubernetes-secrets", Endpoint: "https://kubernetes.example.test", Namespace: "default", TokenRef: ref},
			{TenantID: tenant, ID: "tfc-opentofu", Type: "terraform-cloud-opentofu", Endpoint: "https://app.terraform.io", WorkspaceID: "ws-production", VariableCategory: "env", TokenRef: ref},
			{TenantID: tenant, ID: "vault-kv", Type: "vault-kv-v2", Endpoint: "https://vault.example.test", Mount: "team-secrets", PathPrefix: "apps/production", Field: "value", VaultNamespace: "platform/team-a", TokenRef: ref},
		},
	}
	if err := ValidateSecretIntegrations(cfg, true); err != nil {
		t.Fatalf("all built-ins should validate: %v", err)
	}
}

func TestAWSHoneyAccountRequiresExactOwnerScopeAndCredentialRefs(t *testing.T) {
	base := AWSHoneyAccountConfig{ // #nosec G101 -- test-only file reference paths, no credential values (CWE-798)
		TenantID: "11111111-1111-4111-8111-111111111111", ID: "security-account",
		AccountID: "123456789012", Regions: []string{"us-east-1", "eu-west-1"},
		IAMCredentialsRef:        "file:/var/lib/trstctl/iam-session.json",
		CloudTrailCredentialsRef: "file:/var/lib/trstctl/cloudtrail-session.json",
		MaxTTL:                   "720h", PollInterval: "5m",
	}
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{HoneyAWSAccounts: []AWSHoneyAccountConfig{base}}, true); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*AWSHoneyAccountConfig)
	}{
		{"wrong account", func(c *AWSHoneyAccountConfig) { c.AccountID = "123" }},
		{"no regions", func(c *AWSHoneyAccountConfig) { c.Regions = nil }},
		{"duplicate region", func(c *AWSHoneyAccountConfig) { c.Regions = []string{"us-east-1", "us-east-1"} }},
		{"unknown endpoint region", func(c *AWSHoneyAccountConfig) {
			c.CloudTrailEndpoints = map[string]string{"ap-south-1": "https://cloudtrail.example.test"}
		}},
		{"inline credential", func(c *AWSHoneyAccountConfig) { c.IAMCredentialsRef = "inline-secret" }},
		{"unbounded lifetime", func(c *AWSHoneyAccountConfig) { c.MaxTTL = "9000h" }},
		{"rapid polling", func(c *AWSHoneyAccountConfig) { c.PollInterval = "1s" }},
		{"private without allowlist", func(c *AWSHoneyAccountConfig) { c.IAMEndpoint = "https://127.0.0.1:4566" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := base
			tc.edit(&item)
			if err := ValidateSecretIntegrations(SecretIntegrationsConfig{HoneyAWSAccounts: []AWSHoneyAccountConfig{item}}, true); err == nil {
				t.Fatal("unsafe AWS honeytoken account accepted")
			}
		})
	}
}

func TestValidateKubernetesTokenLeaseConfiguration(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "k8s", Type: "kubernetes", Endpoint: "https://kubernetes.example.test", Namespace: "apps", BearerTokenRef: "file:/run/secrets/kubernetes-admin-token", KubernetesAudience: "https://kubernetes.example.test", AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "Role/reader"}, MaxTTL: "10m"}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	bad := base
	bad.KubernetesAudience = ""
	if err := check(bad); err == nil || !strings.Contains(err.Error(), "kubernetes_audience") {
		t.Fatalf("missing audience = %v", err)
	}
	bad = base
	bad.MaxTTL = "9m"
	if err := check(bad); err == nil || !strings.Contains(err.Error(), "at least 10 minutes") {
		t.Fatalf("short maximum = %v", err)
	}
	bad = base
	bad.KubernetesTLSServerName = "kubernetes.default.svc"
	if err := check(bad); err == nil || !strings.Contains(err.Error(), "requires kubernetes_tls_ca_ref") {
		t.Fatalf("untrusted name override = %v", err)
	}
}

// A239: a TOTP provider names a seed reference and standard code parameters,
// and a lease can't be configured to outlast a code by more than one period.
func TestValidateTOTPProviderA239(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "totp", Type: "totp", SeedRef: "file:/run/secrets/totp-seed", AllowedRoles: []string{"operator"}, MaxTTL: "30s"}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	long := base
	long.Digits, long.Period, long.Algorithm, long.MaxTTL = 8, "60s", "sha512", "60s"
	if err := check(long); err != nil {
		t.Fatalf("8 digits, 60s, SHA512: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no seed":             {func(c *DynamicSecretProviderConfig) { c.SeedRef = "" }, "seed_ref"},
		"five digits":         {func(c *DynamicSecretProviderConfig) { c.Digits = 5 }, "digits must be 6, 7 or 8"},
		"45s period":          {func(c *DynamicSecretProviderConfig) { c.Period = "45s" }, "period must be 30s or 60s"},
		"MD5":                 {func(c *DynamicSecretProviderConfig) { c.Algorithm = "MD5" }, "algorithm must be SHA1"},
		"no max_ttl":          {func(c *DynamicSecretProviderConfig) { c.MaxTTL = "" }, "max_ttl is required for totp"},
		"lease past its code": {func(c *DynamicSecretProviderConfig) { c.MaxTTL = "5m" }, "exceeds the 30s period"},
		"role bindings":       {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"operator": "x"} }, "role_bindings are not used by totp"},
		"ldap fields":         {func(c *DynamicSecretProviderConfig) { c.UsersDN = "ou=x" }, "only valid for ldap"},
	} {
		c := base
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	other := DynamicSecretProviderConfig{TenantID: base.TenantID, ID: "redis", Type: "redis", Addr: "redis.internal:6379", PasswordRef: "file:/run/secrets/redis", RedisTLSServerName: "redis.internal", AllowedRoles: []string{"reader"},
		RedisACLRoles: map[string]redisacl.Role{"reader": {KeyPrefixes: []string{"app:"}, Commands: []string{"get"}}}, SeedRef: "file:/run/secrets/totp-seed"}
	if err := check(other); err == nil || !strings.Contains(err.Error(), "only valid for totp") {
		t.Fatalf("a seed on another provider type = %v", err)
	}
}

func TestValidateOAuthClientCredentialsProviderA239(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "orders-api", Type: "oauth-client-credentials",
		Endpoint: "https://login.example/realms/lab/protocol/openid-connect/token", ClientID: "trstctl-leases",
		ClientSecretRef: "file:/run/secrets/oauth-client", AllowedRoles: []string{"reader", "writer"}, MaxTTL: "5m",
		RoleBindings: map[string]string{"reader": "orders.read", "writer": "orders.read orders.write"}}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	confirmed := base
	confirmed.RevocationEndpoint = "https://login.example/realms/lab/protocol/openid-connect/revoke"
	if err := check(confirmed); err != nil {
		t.Fatalf("with a revocation endpoint: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no token endpoint":   {func(c *DynamicSecretProviderConfig) { c.Endpoint = "" }, "endpoint (the token endpoint) is required"},
		"plain http":          {func(c *DynamicSecretProviderConfig) { c.Endpoint = "http://login.example/token" }, "endpoint:"},
		"http revocation":     {func(c *DynamicSecretProviderConfig) { c.RevocationEndpoint = "http://login.example/revoke" }, "revocation_endpoint:"},
		"no client":           {func(c *DynamicSecretProviderConfig) { c.ClientID = "" }, "client_id is required"},
		"spaced client":       {func(c *DynamicSecretProviderConfig) { c.ClientID = " trstctl" }, "client_id is required"},
		"no secret":           {func(c *DynamicSecretProviderConfig) { c.ClientSecretRef = "" }, "client_secret_ref"},
		"no max_ttl":          {func(c *DynamicSecretProviderConfig) { c.MaxTTL = "" }, "max_ttl is required for oauth-client-credentials"},
		"role without scopes": {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"reader": "orders.read"} }, `role_bindings["writer"] must list the role's scopes`},
		"malformed scope": {func(c *DynamicSecretProviderConfig) {
			c.RoleBindings = map[string]string{"reader": `orders"read`, "writer": "w"}
		}, "not an RFC 6749 scope-token"},
		"binding without role": {func(c *DynamicSecretProviderConfig) { c.RoleBindings["admin"] = "admin" }, `role_bindings["admin"] has no matching allowed role`},
		"totp fields":          {func(c *DynamicSecretProviderConfig) { c.SeedRef = "file:/run/secrets/seed" }, "only valid for totp"},
	} {
		c := base
		c.RoleBindings = map[string]string{"reader": "orders.read", "writer": "orders.read orders.write"}
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	other := DynamicSecretProviderConfig{TenantID: base.TenantID, ID: "totp", Type: "totp", SeedRef: "file:/run/secrets/totp-seed",
		AllowedRoles: []string{"operator"}, MaxTTL: "30s", ClientID: "trstctl-leases"}
	if err := check(other); err == nil || !strings.Contains(err.Error(), "only valid for oauth-client-credentials") {
		t.Fatalf("a client_id on another provider type = %v", err)
	}
}

func TestValidateClickHouseProviderA239(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "warehouse", Type: "clickhouse",
		Endpoint: "https://clickhouse.internal:8443", AdminUser: "trstctl_admin", PasswordRef: "file:/run/secrets/clickhouse-admin",
		AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "orders_reader"}, MaxTTL: "1h"}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no endpoint":          {func(c *DynamicSecretProviderConfig) { c.Endpoint = "" }, "endpoint (the HTTP interface) is required"},
		"plain http":           {func(c *DynamicSecretProviderConfig) { c.Endpoint = "http://clickhouse.internal:8123" }, "endpoint:"},
		"no admin":             {func(c *DynamicSecretProviderConfig) { c.AdminUser = "" }, "admin_user is required for clickhouse"},
		"quoted admin":         {func(c *DynamicSecretProviderConfig) { c.AdminUser = "admin`x" }, "admin_user is required for clickhouse"},
		"no password":          {func(c *DynamicSecretProviderConfig) { c.PasswordRef = "" }, "password_ref"},
		"role without binding": {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{} }, `role_bindings["reader"] must name an existing ClickHouse role`},
		"injected binding": {func(c *DynamicSecretProviderConfig) {
			c.RoleBindings = map[string]string{"reader": "r TO x; DROP USER y"}
		}, "must name an existing ClickHouse role"},
		"binding without role": {func(c *DynamicSecretProviderConfig) { c.RoleBindings["admin"] = "admin_role" }, `role_bindings["admin"] has no matching allowed role`},
	} {
		c := base
		c.RoleBindings = map[string]string{"reader": "orders_reader"}
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	other := DynamicSecretProviderConfig{TenantID: base.TenantID, ID: "totp", Type: "totp", SeedRef: "file:/run/secrets/totp-seed",
		AllowedRoles: []string{"operator"}, MaxTTL: "30s", AdminUser: "trstctl_admin"}
	if err := check(other); err == nil || !strings.Contains(err.Error(), "admin_user is only valid for cassandra, clickhouse, couchbase, elasticsearch, kafka, milvus, rabbitmq, snowflake, unix") {
		t.Fatalf("an admin_user on another provider type = %v", err)
	}
}

func TestValidateElasticsearchProviderA239(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "logs", Type: "elasticsearch",
		Endpoint: "https://es.internal:9200", AdminUser: "trstctl_keys", PasswordRef: "file:/run/secrets/es-admin",
		AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "read,view_index_metadata on logs-*"}, MaxTTL: "1h"}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no endpoint":          {func(c *DynamicSecretProviderConfig) { c.Endpoint = "" }, "endpoint is required for elasticsearch"},
		"plain http":           {func(c *DynamicSecretProviderConfig) { c.Endpoint = "http://es.internal:9200" }, "endpoint:"},
		"no admin":             {func(c *DynamicSecretProviderConfig) { c.AdminUser = "" }, "admin_user is required for elasticsearch"},
		"no password":          {func(c *DynamicSecretProviderConfig) { c.PasswordRef = "" }, "password_ref"},
		"no grant":             {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{} }, `role_bindings["reader"]: must be "<index privileges> on <index patterns>"`},
		"bad privilege":        {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"reader": "Read on logs-*"} }, "is not a privilege name"},
		"bad pattern":          {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"reader": `read on logs"*`} }, "is not an index name or pattern"},
		"binding without role": {func(c *DynamicSecretProviderConfig) { c.RoleBindings["admin"] = "all on *" }, `role_bindings["admin"] has no matching allowed role`},
	} {
		c := base
		c.RoleBindings = map[string]string{"reader": "read,view_index_metadata on logs-*"}
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestValidateRabbitMQProviderA239(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "broker", Type: "rabbitmq",
		Endpoint: "https://rabbit.internal:15671", AdminUser: "trstctl_admin", PasswordRef: "file:/run/secrets/rabbit-admin",
		AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "read on orders,orders.dlq in /"}, MaxTTL: "1h"}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no endpoint":    {func(c *DynamicSecretProviderConfig) { c.Endpoint = "" }, "endpoint (the management API) is required for rabbitmq"},
		"plain http":     {func(c *DynamicSecretProviderConfig) { c.Endpoint = "http://rabbit.internal:15672" }, "endpoint:"},
		"no admin":       {func(c *DynamicSecretProviderConfig) { c.AdminUser = "" }, "admin_user is required for rabbitmq"},
		"no password":    {func(c *DynamicSecretProviderConfig) { c.PasswordRef = "" }, "password_ref"},
		"no grant":       {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{} }, `must be "<permissions> on <resources> in <vhost>"`},
		"regex resource": {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"reader": "read on .* in /"} }, "is not a literal queue or exchange name"},
		"bad permission": {func(c *DynamicSecretProviderConfig) {
			c.RoleBindings = map[string]string{"reader": "admin on orders in /"}
		}, "is not configure, write or read"},
		"binding without role": {func(c *DynamicSecretProviderConfig) { c.RoleBindings["admin"] = "write on x in /" }, `role_bindings["admin"] has no matching allowed role`},
	} {
		c := base
		c.RoleBindings = map[string]string{"reader": "read on orders,orders.dlq in /"}
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestValidateKafkaProviderA239(t *testing.T) {
	grant := "read,describe on topic:orders; read on group:orders-app"
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "events", Type: "kafka",
		Addr: "kafka.internal:9093", AdminUser: "trstctl_admin", PasswordRef: "file:/run/secrets/kafka-admin",
		TLSCARef: "file:/run/secrets/kafka-ca.pem", AllowedRoles: []string{"consumer"}, MaxTTL: "1h"}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	base.RoleBindings = map[string]string{"consumer": grant}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	lab := base
	lab.Addr, lab.TLSCARef, lab.AllowPlaintext = "127.0.0.1:9092", "", true
	if err := check(lab); err != nil {
		t.Fatalf("plaintext SASL at loopback: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no addr":         {func(c *DynamicSecretProviderConfig) { c.Addr = "" }, "addr must be host:port"},
		"no admin":        {func(c *DynamicSecretProviderConfig) { c.AdminUser = "" }, "admin_user is required for kafka"},
		"no password":     {func(c *DynamicSecretProviderConfig) { c.PasswordRef = "" }, "password_ref"},
		"IP without name": {func(c *DynamicSecretProviderConfig) { c.Addr = "10.0.0.5:9093" }, "tls_server_name is required"},
		"plaintext public": {func(c *DynamicSecretProviderConfig) {
			c.Addr, c.TLSCARef, c.AllowPlaintext = "203.0.113.7:9092", "", true
		}, "literal loopback or private IP"},
		"plaintext with TLS": {func(c *DynamicSecretProviderConfig) { c.Addr, c.AllowPlaintext = "127.0.0.1:9092", true }, "allow_plaintext forbids TLS settings"},
		"no grant":           {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{} }, `role_bindings["consumer"] is required for kafka`},
		"every topic": {func(c *DynamicSecretProviderConfig) {
			c.RoleBindings = map[string]string{"consumer": "read on topic:*"}
		}, "is not topic:, group: or transactional_id:"},
		"cluster": {func(c *DynamicSecretProviderConfig) {
			c.RoleBindings = map[string]string{"consumer": "alter on cluster:kafka-cluster"}
		}, "is not topic:, group: or transactional_id:"},
		"bad operation": {func(c *DynamicSecretProviderConfig) {
			c.RoleBindings = map[string]string{"consumer": "all on topic:orders"}
		}, "is not read, write, describe"},
		"binding without role": {func(c *DynamicSecretProviderConfig) { c.RoleBindings["admin"] = "write on topic:x" }, `role_bindings["admin"] has no matching allowed role`},
	} {
		c := base
		c.RoleBindings = map[string]string{"consumer": grant}
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	other := base
	other.Type, other.Addr, other.AdminUser, other.TLSCARef = "redis", "redis.internal:6380", "", ""
	other.AllowPlaintext = true
	if err := check(other); err == nil || !strings.Contains(err.Error(), "allow_plaintext are not valid for redis") {
		t.Fatalf("shared TLS settings on another type: %v", err)
	}
}

func TestValidateCouchbaseProviderA239(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "cache", Type: "couchbase",
		Endpoint: "https://cb.internal:18091", AdminUser: "trstctl_admin", PasswordRef: "file:/run/secrets/couchbase-admin",
		AllowedRoles: []string{"orders"}, MaxTTL: "1h"}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	base.RoleBindings = map[string]string{"orders": "bucket_full_access on orders"}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no endpoint": {func(c *DynamicSecretProviderConfig) { c.Endpoint = "" }, "endpoint (the management REST API) is required for couchbase"},
		"no admin":    {func(c *DynamicSecretProviderConfig) { c.AdminUser = "" }, "admin_user is required for couchbase"},
		"no password": {func(c *DynamicSecretProviderConfig) { c.PasswordRef = "" }, "password_ref"},
		"no grant":    {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{} }, `role_bindings["orders"] is required for couchbase`},
		"no on":       {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"orders": "admin"} }, `must be "<roles> on <buckets>"`},
		"bad role": {func(c *DynamicSecretProviderConfig) {
			c.RoleBindings = map[string]string{"orders": "Data_Reader on orders"}
		}, "is not a Couchbase role name"},
		"bad keyspace": {func(c *DynamicSecretProviderConfig) {
			c.RoleBindings = map[string]string{"orders": "data_reader on a:b:c:d"}
		}, "is not a bucket or bucket:scope:collection"},
		"binding extra": {func(c *DynamicSecretProviderConfig) { c.RoleBindings["admin"] = "bucket_full_access on x" }, `role_bindings["admin"] has no matching allowed role`},
	} {
		c := base
		c.RoleBindings = map[string]string{"orders": "bucket_full_access on orders"}
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestValidateMilvusProviderA239(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "vectors", Type: "milvus",
		Endpoint: "https://milvus.internal:19530", AdminUser: "root", PasswordRef: "file:/run/secrets/milvus-root",
		AllowedRoles: []string{"reader"}, MaxTTL: "1h"}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	base.RoleBindings = map[string]string{"reader": "orders_reader"}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no endpoint":    {func(c *DynamicSecretProviderConfig) { c.Endpoint = "" }, "endpoint (the RESTful API) is required for milvus"},
		"no admin":       {func(c *DynamicSecretProviderConfig) { c.AdminUser = "" }, "admin_user is required for milvus"},
		"colon in admin": {func(c *DynamicSecretProviderConfig) { c.AdminUser = "root:x" }, "must not contain a colon"},
		"no password":    {func(c *DynamicSecretProviderConfig) { c.PasswordRef = "" }, "password_ref"},
		"no grant":       {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{} }, `role_bindings["reader"] is required for milvus`},
		"bad role":       {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"reader": "orders reader"} }, "is not a Milvus role name"},
	} {
		c := base
		c.RoleBindings = map[string]string{"reader": "orders_reader"}
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestValidateLDAPRotationAccountsA240(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "directory", Type: "ldap",
		Addr: "ldap.lab.test:636", BindDN: "cn=admin,dc=lab,dc=test", PasswordRef: "file:/run/secrets/ldap-admin",
		UsersDN: "ou=services,dc=lab,dc=test", AllowedRoles: []string{"directory/orders"},
		RoleBindings: map[string]string{"directory/orders": "cn=orders-readers,ou=groups,dc=lab,dc=test"},
		MaxTTL:       "1h", AllowStaticRotation: true}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	ok := base
	ok.RotationAccounts = map[string][]string{"directory/orders": {"uid=orders-svc-a,ou=services,dc=lab,dc=test", "uid=orders-svc-b,ou=services,dc=lab,dc=test"}}
	if err := check(ok); err != nil {
		t.Fatal(err)
	}
	outside := base
	outside.RotationAccounts = map[string][]string{"directory/orders": {"uid=orders-svc-a,ou=services,dc=lab,dc=test", "uid=root,ou=admins,dc=lab,dc=test"}}
	if err := check(outside); err == nil || !strings.Contains(err.Error(), "is not an entry under users_dn") {
		t.Fatalf("an entry outside users_dn: %v", err)
	}
	if !StaticRotationProviderTypes["ldap"] || !TwoUserRotationProviderTypes["ldap"] {
		t.Fatal("ldap must rotate statically between two entries")
	}
}

func TestValidateUnixProviderA240(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "orders-host", Type: "unix",
		Addr: "10.0.0.20:22", AdminUser: "root", PrivateKeyRef: "file:/run/secrets/host-admin-key",
		HostKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), AllowedRoles: []string{"host/orders", "host/single"},
		MaxTTL: "1h", AllowStaticRotation: true}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	valid := func() DynamicSecretProviderConfig {
		c := base
		c.RoleBindings = map[string]string{"host/single": "orders-single"}
		c.RotationAccounts = map[string][]string{"host/orders": {"orders-svc-a", "orders-svc-b"}}
		return c
	}
	if err := check(valid()); err != nil {
		t.Fatal(err)
	}
	if !StaticRotationProviderTypes["unix"] || !TwoUserRotationProviderTypes["unix"] || SinglePhaseRotationProviderTypes["unix"] {
		t.Fatal("unix rotates statically, two-user per role; its single phase is per role, not per type")
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no addr":      {func(c *DynamicSecretProviderConfig) { c.Addr = "" }, "addr must be the host's SSH host:port"},
		"bad admin":    {func(c *DynamicSecretProviderConfig) { c.AdminUser = "Root User" }, "admin_user must be a local account"},
		"no key":       {func(c *DynamicSecretProviderConfig) { c.PrivateKeyRef = "" }, "private_key_ref"},
		"no pin":       {func(c *DynamicSecretProviderConfig) { c.HostKeyFingerprint = "" }, "host_key_fingerprint must pin the host key"},
		"leases":       {func(c *DynamicSecretProviderConfig) { c.AllowStaticRotation = false }, "issues no leases"},
		"unbound role": {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{} }, `role_bindings["host/single"] must name the local account`},
		"bad account":  {func(c *DynamicSecretProviderConfig) { c.RoleBindings["host/single"] = "root:0:0" }, `role_bindings["host/single"] must name the local account`},
		"bad pair": {func(c *DynamicSecretProviderConfig) {
			c.RotationAccounts["host/orders"] = []string{"orders-svc-a", "Orders B"}
		}, "is not a local account name"},
		"sudo elsewhere": {func(c *DynamicSecretProviderConfig) { c.Type, c.Sudo = "ldap", true }, "host_key_fingerprint and sudo are only valid for unix"},
	} {
		c := valid()
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestValidateRotationAccountsA240(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "orders", Type: "postgresql",
		AdminDSNRef: "file:/run/secrets/orders-admin-dsn", AllowedRoles: []string{"db/orders", "db/reports"}, MaxTTL: "1h",
		AllowStaticRotation: true}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	pairs := func() map[string][]string {
		return map[string][]string{"db/orders": {"orders_app_a", "orders_app_b"}, "db/reports": {"reports_a", "reports_b"}}
	}
	ok := base
	ok.RotationAccounts = pairs()
	if err := check(ok); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"not opted in":   {func(c *DynamicSecretProviderConfig) { c.AllowStaticRotation = false }, "rotation_accounts needs allow_static_rotation on a provider of type azure-sql or ldap or mongodb or mssql or oracle or postgresql or unix"},
		"wrong type":     {func(c *DynamicSecretProviderConfig) { c.Type = "mysql" }, "rotation_accounts needs allow_static_rotation on a provider of type azure-sql or ldap or mongodb or mssql or oracle or postgresql or unix"},
		"unknown role":   {func(c *DynamicSecretProviderConfig) { c.RotationAccounts["db/other"] = []string{"x_a", "x_b"} }, `role "db/other" is not in allowed_roles`},
		"one account":    {func(c *DynamicSecretProviderConfig) { c.RotationAccounts["db/orders"] = []string{"orders_app_a"} }, "needs two distinct account names"},
		"same account":   {func(c *DynamicSecretProviderConfig) { c.RotationAccounts["db/orders"] = []string{"a", "a"} }, "needs two distinct account names"},
		"padded account": {func(c *DynamicSecretProviderConfig) { c.RotationAccounts["db/orders"] = []string{" a", "b"} }, "needs two distinct account names"},
		"long account": {func(c *DynamicSecretProviderConfig) {
			c.RotationAccounts["db/orders"] = []string{strings.Repeat("a", 64), "b"}
		}, "is not a PostgreSQL role name"},
		"shared account": {func(c *DynamicSecretProviderConfig) {
			c.RotationAccounts["db/reports"] = []string{"orders_app_b", "reports_b"}
		}, `account "orders_app_b" serves roles`},
	} {
		c := base
		c.RotationAccounts = pairs()
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestValidateAuth0ProviderA240(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "auth0", Type: "auth0",
		Endpoint: "https://acme.us.auth0.com", ClientID: "mgmtClient001", ClientSecretRef: "file:/run/secrets/auth0-mgmt",
		AllowedRoles: []string{"auth0/orders"}, RoleBindings: map[string]string{"auth0/orders": "appClient0001"}, MaxTTL: "1h",
		AllowStaticRotation: true}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	if !StaticRotationProviderTypes["auth0"] || !SinglePhaseRotationProviderTypes["auth0"] {
		t.Fatal("auth0 must rotate statically, in a single phase")
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no endpoint":     {func(c *DynamicSecretProviderConfig) { c.Endpoint = "" }, "endpoint (the tenant domain) is required for auth0"},
		"bad client":      {func(c *DynamicSecretProviderConfig) { c.ClientID = "mgmt client" }, "client_id must be the management application's client ID"},
		"no secret":       {func(c *DynamicSecretProviderConfig) { c.ClientSecretRef = "" }, "client_secret_ref"},
		"leases":          {func(c *DynamicSecretProviderConfig) { c.AllowStaticRotation = false }, "issues no leases: set allow_static_rotation"},
		"unbound role":    {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{} }, `role_bindings["auth0/orders"]`},
		"binding not app": {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"auth0/orders": "orders app"} }, "must be the Auth0 application client ID"},
	} {
		c := base
		c.RoleBindings = map[string]string{"auth0/orders": "appClient0001"}
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestValidateDatadogProviderA240(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "datadog", Type: "datadog",
		Endpoint: "https://api.datadoghq.com", APIKeyRef: "file:/run/secrets/dd-api", ApplicationKeyRef: "file:/run/secrets/dd-app",
		AllowedRoles: []string{"datadog/ingest", "datadog/metrics"}, MaxTTL: "1h", AllowStaticRotation: true}
	bindings := func() map[string]string {
		return map[string]string{"datadog/ingest": "api_key",
			"datadog/metrics": "application_key 3f1e7e1a-1111-4222-8333-444455556666 metrics_read,timeseries_query"}
	}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	base.RoleBindings = bindings()
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	leases := base
	leases.AllowStaticRotation = false
	if err := check(leases); err != nil {
		t.Fatalf("datadog issues leases too: %v", err)
	}
	if !StaticRotationProviderTypes["datadog"] || SinglePhaseRotationProviderTypes["datadog"] {
		t.Fatal("datadog must rotate statically, in two phases")
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no endpoint":  {func(c *DynamicSecretProviderConfig) { c.Endpoint = "" }, "endpoint (the site's API"},
		"no api key":   {func(c *DynamicSecretProviderConfig) { c.APIKeyRef = "" }, "api_key_ref"},
		"no app key":   {func(c *DynamicSecretProviderConfig) { c.ApplicationKeyRef = "" }, "application_key_ref"},
		"unbound role": {func(c *DynamicSecretProviderConfig) { delete(c.RoleBindings, "datadog/ingest") }, `role_bindings["datadog/ingest"]`},
		"bad kind":     {func(c *DynamicSecretProviderConfig) { c.RoleBindings["datadog/ingest"] = "api_keys" }, `must be "api_key" or`},
		"bad account": {func(c *DynamicSecretProviderConfig) {
			c.RoleBindings["datadog/metrics"] = "application_key admin metrics_read"
		}, "is not a service account ID"},
		"unscoped app": {func(c *DynamicSecretProviderConfig) {
			c.RoleBindings["datadog/metrics"] = "application_key 3f1e7e1a-1111-4222-8333-444455556666"
		}, `must be "api_key" or`},
		"bad scope": {func(c *DynamicSecretProviderConfig) {
			c.RoleBindings["datadog/metrics"] = "application_key 3f1e7e1a-1111-4222-8333-444455556666 Metrics"
		}, "is not an authorization scope"},
		"app key on auth": {func(c *DynamicSecretProviderConfig) { c.Type = "auth0" }, "application_key_ref is only valid for datadog"},
	} {
		c := base
		c.RoleBindings = bindings()
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	other := base
	other.Type, other.APIKeyRef, other.ApplicationKeyRef, other.RoleBindings = "redis", "", "", nil
	other.Addr = "10.0.0.5:6379"
	if err := check(other); err == nil || !strings.Contains(err.Error(), "allow_static_rotation is served for") ||
		!strings.Contains(err.Error(), strings.Join(sortedTrueKeys(StaticRotationProviderTypes), ", ")) {
		t.Fatalf("static rotation on a type without it: %v", err)
	}
}

func TestValidateOpenAIProviderA240(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "openai", Type: "openai",
		Endpoint: "https://api.openai.com", APIKeyRef: "file:/run/secrets/openai-admin", AllowedRoles: []string{"openai/orders"},
		MaxTTL: "1h", AllowStaticRotation: true}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	base.RoleBindings = map[string]string{"openai/orders": "proj_orders01"}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	if !StaticRotationProviderTypes["openai"] || SinglePhaseRotationProviderTypes["openai"] {
		t.Fatal("openai must rotate statically, in two phases")
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no endpoint":   {func(c *DynamicSecretProviderConfig) { c.Endpoint = "" }, "endpoint (the API"},
		"no admin key":  {func(c *DynamicSecretProviderConfig) { c.APIKeyRef = "" }, "api_key_ref"},
		"unbound role":  {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{} }, `role_bindings["openai/orders"]`},
		"not a project": {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"openai/orders": "orders"} }, "must be the project ID"},
		"app key":       {func(c *DynamicSecretProviderConfig) { c.ApplicationKeyRef = "file:/run/secrets/x" }, "application_key_ref is only valid for datadog"},
	} {
		c := base
		c.RoleBindings = map[string]string{"openai/orders": "proj_orders01"}
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

// A240: every hosted API key provider validates its endpoint, its
// administrator's credential and its roles' bindings in the vendor's grammar
// (internal/hostedkey), and rotates statically in two phases.
func TestValidateHostedKeyProvidersA240(t *testing.T) {
	bindings := map[string]string{
		"openrouter": "limit 25", "fireworks": "acme/ci-bot", "litellm": "models gpt-4o", "supabase": "abcdefghijklmnopqrst",
		"convex": "happy-animal-123", "dbt": "70403 job_runner", "cloudflare": "template 0123456789abcdef0123456789abcdef",
		"cloudflare-r2": "account fedcba9876543210fedcba9876543210 template 0123456789abcdef0123456789abcdef",
	}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	for provider, binding := range bindings {
		base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: provider + "-account", Type: provider,
			Endpoint: "https://api.example.com", APIKeyRef: "file:/run/secrets/" + provider, AllowedRoles: []string{"ci"},
			RoleBindings: map[string]string{"ci": binding}, MaxTTL: "1h", AllowStaticRotation: true}
		if err := check(base); err != nil {
			t.Fatalf("%s: %v", provider, err)
		}
		if !StaticRotationProviderTypes[provider] || SinglePhaseRotationProviderTypes[provider] {
			t.Fatalf("%s must rotate statically, in two phases", provider)
		}
		for name, tc := range map[string]struct {
			mutate func(*DynamicSecretProviderConfig)
			want   string
		}{
			"no endpoint":   {func(c *DynamicSecretProviderConfig) { c.Endpoint = "" }, "endpoint ("},
			"no admin key":  {func(c *DynamicSecretProviderConfig) { c.APIKeyRef = "" }, "api_key_ref ("},
			"unbound role":  {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{} }, `role_bindings["ci"] is required`},
			"a bad binding": {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"ci": "every key there is"} }, `role_bindings["ci"]: expected`},
		} {
			c := base
			tc.mutate(&c)
			if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s %s: %v, want %q", provider, name, err, tc.want)
			}
		}
	}
	other := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "pg", Type: "postgresql",
		AdminDSNRef: "file:/run/secrets/pg", APIKeyRef: "file:/run/secrets/key", AllowedRoles: []string{"ci"}, MaxTTL: "1h"}
	if err := check(other); err == nil || !strings.Contains(err.Error(), "api_key_ref is only valid for cloudflare, cloudflare-r2, convex, datadog, dbt, fireworks") {
		t.Fatalf("api_key_ref on a type without it: %v", err)
	}
}

// A240: azure-entra rotates statically; authority_host is its own field,
// validated like an endpoint.
func TestValidateAzureEntraRotationA240(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "entra", Type: "azure-entra",
		Endpoint: "https://graph.microsoft.com", ApplicationObject: "obj", ApplicationClient: "client", AzureTenant: "tenant",
		BearerTokenRef: "file:/run/secrets/graph", AllowedRoles: []string{"app"}, MaxTTL: "1h", AllowStaticRotation: true,
		AuthorityHost: "https://login.microsoftonline.com"}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	if !StaticRotationProviderTypes["azure-entra"] || SinglePhaseRotationProviderTypes["azure-entra"] {
		t.Fatal("azure-entra must rotate statically, in two phases")
	}
	plain := base
	plain.AuthorityHost = "http://login.example"
	if err := check(plain); err == nil || !strings.Contains(err.Error(), "authority_host") {
		t.Fatalf("a plaintext authority host: %v", err)
	}
	other := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "openai", Type: "openai",
		Endpoint: "https://api.openai.com", APIKeyRef: "file:/run/secrets/openai", AllowedRoles: []string{"app"},
		RoleBindings: map[string]string{"app": "proj_orders01"}, MaxTTL: "1h", AuthorityHost: "https://login.microsoftonline.com"}
	if err := check(other); err == nil || !strings.Contains(err.Error(), "authority_host is only valid for azure-entra") {
		t.Fatalf("authority_host on another type: %v", err)
	}
}

func TestValidateMSSQLProvidersA239(t *testing.T) {
	for _, providerType := range []string{"mssql", "azure-sql"} {
		base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "sql", Type: providerType,
			AdminDSNRef: "file:/run/secrets/sql-admin-dsn", Database: "orders", AllowedRoles: []string{"reader"}, MaxTTL: "1h"}
		check := func(c DynamicSecretProviderConfig) error {
			t.Helper()
			return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
		}
		base.RoleBindings = map[string]string{"reader": "db_datareader, report_reader"}
		if err := check(base); err != nil {
			t.Fatalf("%s: %v", providerType, err)
		}
		for name, tc := range map[string]struct {
			mutate func(*DynamicSecretProviderConfig)
			want   string
		}{
			"no dsn":       {func(c *DynamicSecretProviderConfig) { c.AdminDSNRef = "" }, "admin_dsn_ref"},
			"no database":  {func(c *DynamicSecretProviderConfig) { c.Database = "" }, "database is required for " + providerType},
			"bad database": {func(c *DynamicSecretProviderConfig) { c.Database = "orders]; DROP DATABASE x; --" }, "must be a plain database name"},
			"no grant":     {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{} }, `role_bindings["reader"] is required for ` + providerType},
			"bad role": {func(c *DynamicSecretProviderConfig) {
				c.RoleBindings = map[string]string{"reader": "db_datareader]; --"}
			}, "is not a database role name"},
		} {
			c := base
			c.RoleBindings = map[string]string{"reader": "db_datareader, report_reader"}
			tc.mutate(&c)
			if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s %s: %v, want %q", providerType, name, err, tc.want)
			}
		}
	}
}

func TestValidateGitHubAppProviderA239(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "github", Type: "github-app",
		ClientID: "Iv1.0123456789abcdef", PrivateKeyRef: "file:/run/secrets/github-app.pem", InstallationID: "4242",
		AllowedRoles: []string{"ci"}, MaxTTL: "1h"}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	base.RoleBindings = map[string]string{"ci": "contents:read,metadata:read on api,web"}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no client":        {func(c *DynamicSecretProviderConfig) { c.ClientID = "" }, "client_id (the app's client ID) is required"},
		"no key":           {func(c *DynamicSecretProviderConfig) { c.PrivateKeyRef = "" }, "private_key_ref"},
		"bad installation": {func(c *DynamicSecretProviderConfig) { c.InstallationID = "acme" }, "installation_id must be GitHub's numeric"},
		"over an hour":     {func(c *DynamicSecretProviderConfig) { c.MaxTTL = "2h" }, "max_ttl must be at most 1h"},
		"no on":            {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"ci": "contents:read"} }, `must be "<permission>:<level> on <repositories>"`},
		"bad level": {func(c *DynamicSecretProviderConfig) {
			c.RoleBindings = map[string]string{"ci": "contents:owner on api"}
		}, "is not <permission>:read"},
		"every repository": {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"ci": "contents:read on *"} }, "is not a repository name"},
		"secret on github": {func(c *DynamicSecretProviderConfig) { c.ClientSecretRef = "file:/run/secrets/x" }, "client_secret_ref is only valid for"},
	} {
		c := base
		c.RoleBindings = map[string]string{"ci": "contents:read,metadata:read on api,web"}
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	other := base
	other.Type, other.ClientID = "tailscale", ""
	other.BearerTokenRef, other.RoleBindings = "file:/run/secrets/ts", map[string]string{"ci": "tag:ci"}
	if err := check(other); err == nil || !strings.Contains(err.Error(), "installation_id is only valid for github-app") {
		t.Fatalf("github-app fields on another type: %v", err)
	}
}

func TestValidateSnowflakeProviderA239(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "warehouse", Type: "snowflake",
		Endpoint: "https://acme-prod.snowflakecomputing.com", Account: "acme-prod", AdminUser: "TRSTCTL_ADMIN",
		PrivateKeyRef: "file:/run/secrets/snowflake-admin.pem", AllowedRoles: []string{"analyst"}, MaxTTL: "8h"}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	base.RoleBindings = map[string]string{"analyst": "ANALYST, REPORTER"}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no endpoint": {func(c *DynamicSecretProviderConfig) { c.Endpoint = "" }, "endpoint (the account URL) is required for snowflake"},
		"no account":  {func(c *DynamicSecretProviderConfig) { c.Account = "" }, "account (the <orgname>-<accountname> identifier) is required"},
		"no admin":    {func(c *DynamicSecretProviderConfig) { c.AdminUser = "" }, "admin_user is required for snowflake"},
		"no key":      {func(c *DynamicSecretProviderConfig) { c.PrivateKeyRef = "" }, "private_key_ref"},
		"bad role":    {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"analyst": `"ANALYST"`} }, "is not a Snowflake role name"},
		"no grant":    {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{} }, `role_bindings["analyst"] is required for snowflake`},
	} {
		c := base
		c.RoleBindings = map[string]string{"analyst": "ANALYST, REPORTER"}
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	other := base
	other.Type, other.AdminUser, other.PrivateKeyRef = "tailscale", "", ""
	other.BearerTokenRef, other.RoleBindings = "file:/run/secrets/ts", map[string]string{"analyst": "tag:ci"}
	if err := check(other); err == nil || !strings.Contains(err.Error(), "account is only valid for snowflake") {
		t.Fatalf("account on another type: %v", err)
	}
}

func TestValidateAWSCacheProvidersA239(t *testing.T) {
	for _, providerType := range []string{"aws-elasticache", "aws-memorydb"} {
		base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "cache", Type: providerType,
			Region: "us-east-1", AccessKeyID: "AKIAEXAMPLE", SecretAccessRef: "file:/run/secrets/aws-secret", UserGroup: "orders-group",
			AllowedRoles: []string{"reader"}, MaxTTL: "1h",
			RedisACLRoles: map[string]redisacl.Role{"reader": {KeyPrefixes: []string{"orders:"}, Commands: []string{"get"}}}}
		check := func(c DynamicSecretProviderConfig) error {
			t.Helper()
			return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
		}
		if err := check(base); err != nil {
			t.Fatalf("%s: %v", providerType, err)
		}
		for name, tc := range map[string]struct {
			mutate func(*DynamicSecretProviderConfig)
			want   string
		}{
			"no region": {func(c *DynamicSecretProviderConfig) { c.Region = "" }, "region and access_key_id are required"},
			"no secret": {func(c *DynamicSecretProviderConfig) { c.SecretAccessRef = "" }, "secret_access_key_ref"},
			"no group":  {func(c *DynamicSecretProviderConfig) { c.UserGroup = "" }, "user_group (the ElastiCache user group or MemoryDB ACL) is required"},
			"no policy": {func(c *DynamicSecretProviderConfig) { c.RedisACLRoles = nil }, `redis_acl_roles["reader"] is required for ` + providerType},
			"unsafe command": {func(c *DynamicSecretProviderConfig) {
				c.RedisACLRoles = map[string]redisacl.Role{"reader": {KeyPrefixes: []string{"orders:"}, Commands: []string{"flushall"}}}
			}, "outside the safe command set"},
		} {
			c := base
			tc.mutate(&c)
			if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s %s: %v, want %q", providerType, name, err, tc.want)
			}
		}
	}
	memory := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "cache", Type: "aws-memorydb",
		Region: "us-east-1", AccessKeyID: "AKIAEXAMPLE", SecretAccessRef: "file:/run/secrets/aws-secret", UserGroup: "orders-acl", Engine: "valkey",
		AllowedRoles: []string{"reader"}, MaxTTL: "1h",
		RedisACLRoles: map[string]redisacl.Role{"reader": {KeyPrefixes: []string{"orders:"}, Commands: []string{"get"}}}}
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{memory}}, true); err == nil || !strings.Contains(err.Error(), "engine is only valid for aws-elasticache") {
		t.Fatalf("engine on MemoryDB: %v", err)
	}
}

func TestValidateAPIConnectProviderA239(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "apic", Type: "ibm-api-connect",
		Endpoint: "https://apic.internal", ClientID: "toolkit", ClientSecretRef: "file:/run/secrets/apic-client", APIKeyRef: "file:/run/secrets/apic-key",
		AllowedRoles: []string{"partner"}, MaxTTL: "8h"}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	base.RoleBindings = map[string]string{"partner": "acme/sandbox/partners/orders-app"}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no endpoint": {func(c *DynamicSecretProviderConfig) { c.Endpoint = "" }, "endpoint (the platform API) is required"},
		"no client":   {func(c *DynamicSecretProviderConfig) { c.ClientID = "" }, "client_id is required for ibm-api-connect"},
		"no api key":  {func(c *DynamicSecretProviderConfig) { c.APIKeyRef = "" }, "api_key_ref"},
		"bad app":     {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"partner": "orders-app"} }, `must be "<org>/<catalog>/<consumer-org>/<app>"`},
	} {
		c := base
		c.RoleBindings = map[string]string{"partner": "acme/sandbox/partners/orders-app"}
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestValidateCassandraProviderA239(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "orders-cassandra", Type: "cassandra",
		Addr: "cassandra.internal:9142", AdminUser: "trstctl_admin", PasswordRef: "file:/run/secrets/cassandra-admin",
		TLSCARef: "file:/run/secrets/cassandra-ca.pem", AllowedRoles: []string{"reader"}, MaxTTL: "1h"}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	base.RoleBindings = map[string]string{"reader": "orders_reader, audit_reader"}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	lab := base
	lab.Addr, lab.TLSCARef, lab.AllowPlaintext = "127.0.0.1:9042", "", true
	if err := check(lab); err != nil {
		t.Fatalf("plaintext at loopback: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no addr":         {func(c *DynamicSecretProviderConfig) { c.Addr = "" }, "addr must be host:port"},
		"no admin":        {func(c *DynamicSecretProviderConfig) { c.AdminUser = "" }, "admin_user is required for cassandra"},
		"no password":     {func(c *DynamicSecretProviderConfig) { c.PasswordRef = "" }, "password_ref"},
		"IP without name": {func(c *DynamicSecretProviderConfig) { c.Addr = "10.0.0.5:9142" }, "tls_server_name is required"},
		"plaintext public": {func(c *DynamicSecretProviderConfig) {
			c.Addr, c.TLSCARef, c.AllowPlaintext = "203.0.113.7:9042", "", true
		}, "literal loopback or private IP"},
		"no binding": {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{} }, `role_bindings["reader"] is required for cassandra`},
		"quoted role": {func(c *DynamicSecretProviderConfig) {
			c.RoleBindings = map[string]string{"reader": `orders"; DROP ROLE cassandra; --`}
		}, "is not a plain Cassandra role name"},
	} {
		c := base
		c.RoleBindings = map[string]string{"reader": "orders_reader"}
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestValidateOracleProviderA239(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "orders-oracle", Type: "oracle",
		AdminDSNRef: "file:/run/secrets/oracle-admin-url", AllowedRoles: []string{"reader", "app"}, MaxTTL: "1h",
		AllowStaticRotation: true,
		RoleBindings:        map[string]string{"reader": "ORDERS_READER, AUDIT_READER"},
		RotationAccounts:    map[string][]string{"app": {"ORDERS_APP_A", "ORDERS_APP_B"}}}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no admin URL": {func(c *DynamicSecretProviderConfig) { c.AdminDSNRef = "" }, "admin_dsn_ref"},
		"unbound role": {func(c *DynamicSecretProviderConfig) { c.RotationAccounts = nil }, `role_bindings["app"] or rotation_accounts["app"] is required for oracle`},
		"quoted role": {func(c *DynamicSecretProviderConfig) {
			c.RoleBindings = map[string]string{"reader": `ORDERS_READER" TO PUBLIC --`}
		}, "is not an Oracle role name"},
		"binding without role": {func(c *DynamicSecretProviderConfig) {
			c.RoleBindings = map[string]string{"reader": "ORDERS_READER", "admin": "DBA"}
		}, `role_bindings["admin"] has no matching allowed role`},
		"bad account": {func(c *DynamicSecretProviderConfig) {
			c.RotationAccounts = map[string][]string{"app": {"ORDERS_APP_A", "1ORDERS"}}
		}, "is not an Oracle user name"},
		"not opted in": {func(c *DynamicSecretProviderConfig) { c.AllowStaticRotation = false }, "rotation_accounts needs allow_static_rotation"},
	} {
		c := base
		c.RoleBindings = map[string]string{"reader": "ORDERS_READER"}
		c.RotationAccounts = map[string][]string{"app": {"ORDERS_APP_A", "ORDERS_APP_B"}}
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestValidateHANAProviderA239(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "warehouse-hana", Type: "hana",
		AdminDSNRef: "file:/run/secrets/hana-admin-url", AllowedRoles: []string{"reader"}, MaxTTL: "1h",
		RoleBindings: map[string]string{"reader": "ORDERS_READER, AUDIT_READER"}}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no admin URL": {func(c *DynamicSecretProviderConfig) { c.AdminDSNRef = "" }, "admin_dsn_ref"},
		"no binding":   {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{} }, `role_bindings["reader"] is required for hana`},
		"quoted role": {func(c *DynamicSecretProviderConfig) {
			c.RoleBindings = map[string]string{"reader": `ORDERS" TO PUBLIC --`}
		}, "is not a HANA role name"},
		"static rotation": {func(c *DynamicSecretProviderConfig) {
			c.AllowStaticRotation, c.RotationAccounts = true, map[string][]string{"reader": {"APP_A", "APP_B"}}
		}, "rotation_accounts needs allow_static_rotation on a provider of type"},
	} {
		c := base
		c.RoleBindings = map[string]string{"reader": "ORDERS_READER"}
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestValidateTailscaleProviderA239(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "tailnet", Type: "tailscale",
		BearerTokenRef: "file:/run/secrets/tailscale-api", AllowedRoles: []string{"ci"},
		RoleBindings: map[string]string{"ci": "tag:ci,tag:build"}, MaxTTL: "1h"}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	named := base
	named.Tailnet, named.Endpoint = "example.com", "https://api.tailscale.com"
	if err := check(named); err != nil {
		t.Fatalf("named tailnet: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no token":             {func(c *DynamicSecretProviderConfig) { c.BearerTokenRef = "" }, "bearer_token_ref (the Tailscale API token)"},
		"bad tailnet":          {func(c *DynamicSecretProviderConfig) { c.Tailnet = "a/b" }, "is not a tailnet name"},
		"untagged role":        {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"ci": "ci"} }, "must list ACL tags"},
		"binding without role": {func(c *DynamicSecretProviderConfig) { c.RoleBindings["ops"] = "tag:ops" }, `role_bindings["ops"] has no matching allowed role`},
	} {
		c := base
		c.RoleBindings = map[string]string{"ci": "tag:ci,tag:build"}
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	other := DynamicSecretProviderConfig{TenantID: base.TenantID, ID: "totp", Type: "totp", SeedRef: "file:/run/secrets/totp-seed",
		AllowedRoles: []string{"operator"}, MaxTTL: "30s", Tailnet: "example.com"}
	if err := check(other); err == nil || !strings.Contains(err.Error(), "tailnet is only valid for tailscale") {
		t.Fatalf("a tailnet on another provider type = %v", err)
	}
}

func TestValidateMongoDBAtlasProviderA239(t *testing.T) {
	base := DynamicSecretProviderConfig{TenantID: "11111111-1111-1111-1111-111111111111", ID: "atlas", Type: "mongodb-atlas",
		Project: "5f1e2d3c4b5a69788796a5b4", ClientID: "mdb_sa_id_trstctl", ClientSecretRef: "file:/run/secrets/atlas-sa",
		AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "read on orders,inventory"}, MaxTTL: "8h"}
	check := func(c DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
	}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		mutate func(*DynamicSecretProviderConfig)
		want   string
	}{
		"no project":           {func(c *DynamicSecretProviderConfig) { c.Project = "" }, "project (the Atlas project ID"},
		"no client":            {func(c *DynamicSecretProviderConfig) { c.ClientID = "" }, "client_id (the Atlas service account)"},
		"no secret":            {func(c *DynamicSecretProviderConfig) { c.ClientSecretRef = "" }, "client_secret_ref"},
		"over a week":          {func(c *DynamicSecretProviderConfig) { c.MaxTTL = "200h" }, "exceeds the seven days"},
		"bad role":             {func(c *DynamicSecretProviderConfig) { c.RoleBindings = map[string]string{"reader": "read"} }, `must be "<role> on <databases>"`},
		"binding without role": {func(c *DynamicSecretProviderConfig) { c.RoleBindings["admin"] = "dbAdmin on x" }, `role_bindings["admin"] has no matching allowed role`},
		"revocation endpoint":  {func(c *DynamicSecretProviderConfig) { c.RevocationEndpoint = "https://x/revoke" }, "revocation_endpoint is only valid for oauth-client-credentials"},
	} {
		c := base
		c.RoleBindings = map[string]string{"reader": "read on orders,inventory"}
		tc.mutate(&c)
		if err := check(c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestValidateRedisACLRequiresExplicitScopedRoles(t *testing.T) {
	base := DynamicSecretProviderConfig{
		TenantID: "11111111-1111-1111-1111-111111111111", ID: "redis", Type: "redis",
		Addr: "redis.internal:6379", PasswordRef: "file:/run/secrets/redis-admin", RedisTLSServerName: "redis.internal",
		AllowedRoles: []string{"reader", "writer"},
		RedisACLRoles: map[string]redisacl.Role{
			"reader": {KeyPrefixes: []string{"app:"}, Commands: []string{"get"}},
			"writer": {KeyPrefixes: []string{"app:"}, Commands: []string{"get", "set", "del"}},
		},
	}
	validate := func(cfg DynamicSecretProviderConfig) error {
		t.Helper()
		return ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{cfg}}, true)
	}
	if err := validate(base); err != nil {
		t.Fatalf("scoped Redis ACL rejected: %v", err)
	}
	bad := base
	bad.RedisACLRoles = map[string]redisacl.Role{"reader": base.RedisACLRoles["reader"]}
	if err := validate(bad); err == nil || !strings.Contains(err.Error(), "redis_acl_roles[\"writer\"]") {
		t.Fatalf("missing writer ACL error = %v", err)
	}
	bad = base
	bad.RedisACLRoles = map[string]redisacl.Role{
		"reader": {KeyPrefixes: []string{"*"}, Commands: []string{"get"}},
		"writer": base.RedisACLRoles["writer"],
	}
	if err := validate(bad); err == nil || !strings.Contains(err.Error(), "key prefix") {
		t.Fatalf("global key scope error = %v", err)
	}
	bad = base
	bad.RedisACLRoles = map[string]redisacl.Role{
		"reader": base.RedisACLRoles["reader"],
		"writer": {KeyPrefixes: []string{"app:"}, Commands: []string{"config"}},
	}
	if err := validate(bad); err == nil || !strings.Contains(err.Error(), "safe command set") {
		t.Fatalf("admin command error = %v", err)
	}
	bad = base
	bad.PasswordRef = ""
	if err := validate(bad); err == nil || !strings.Contains(err.Error(), "password_ref") {
		t.Fatalf("anonymous admin error = %v", err)
	}
	bad = base
	bad.RedisTLSServerName = ""
	if err := validate(bad); err == nil || !strings.Contains(err.Error(), "redis_tls_server_name") {
		t.Fatalf("missing verified transport error = %v", err)
	}
	bad = base
	bad.DB = 1
	if err := validate(bad); err == nil || !strings.Contains(err.Error(), "db must be 0") {
		t.Fatalf("Redis logical database scope error = %v", err)
	}
	bad = base
	bad.AllowPlaintextRedis = true
	bad.RedisTLSServerName = ""
	if err := validate(bad); err == nil || !strings.Contains(err.Error(), "literal loopback or private IP") {
		t.Fatalf("plaintext public or DNS address error = %v", err)
	}
}

func TestValidateMySQLAccountHostRequiresExplicitScope(t *testing.T) {
	base := DynamicSecretProviderConfig{
		TenantID: "11111111-1111-1111-1111-111111111111", ID: "mysql", Type: "mysql",
		AdminDSNRef: "file:/run/secrets/mysql-admin-dsn", Database: "app", Addr: "mysql.internal:3306",
		AllowedRoles: []string{"reader"},
	}
	check := func(c DynamicSecretProviderConfig, want string) {
		t.Helper()
		err := ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{c}}, true)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("MySQL account host validation = %v, want %q", err, want)
		}
	}
	check(base, "account_host")
	wildcard := base
	wildcard.AccountHost = "%"
	check(wildcard, "allow_wildcard_account_host")
	wildcard.AllowWildcardAccountHost = true
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{wildcard}}, true); err != nil {
		t.Fatalf("explicit wildcard opt-in rejected: %v", err)
	}
	exact := base
	exact.AccountHost = "10.4.0.12"
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{exact}}, true); err != nil {
		t.Fatalf("exact account host rejected: %v", err)
	}
}

func TestValidateSecretIntegrationsAWSFederatedIsExplicitAndRejectsStaticFallback(t *testing.T) {
	base := SecretSyncTargetConfig{
		TenantID: "11111111-1111-1111-1111-111111111111",
		ID:       "aws-federated", Type: "aws-secrets-manager",
		Endpoint: "https://secretsmanager.us-east-1.amazonaws.com",
		Region:   "us-east-1", AWSWorkloadIdentity: true,
	}
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{base}}, true); err != nil {
		t.Fatalf("explicit AWS workload identity target rejected: %v", err)
	}
	withStatic := base
	withStatic.AccessKeyID = "AKID"
	withStatic.SecretAccessRef = "file:/run/secrets/aws"
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{withStatic}}, true); err == nil ||
		!strings.Contains(err.Error(), "forbids static") {
		t.Fatalf("AWS workload identity with static fallback error = %v", err)
	}
	implicit := base
	implicit.AWSWorkloadIdentity = false
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{implicit}}, true); err == nil ||
		!strings.Contains(err.Error(), "access_key_id") {
		t.Fatalf("implicit AWS workload identity target error = %v", err)
	}
}

func TestValidateSecretIntegrationsGCPFederatedIsExplicitAndRejectsStaticFallback(t *testing.T) {
	base := SecretSyncTargetConfig{
		TenantID: "11111111-1111-1111-1111-111111111111",
		ID:       "gcp-federated", Type: "gcp-secret-manager",
		Endpoint: "https://secretmanager.googleapis.com",
		Project:  "payments-production", GCPWorkloadIdentity: true,
	}
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{base}}, true); err != nil {
		t.Fatalf("explicit GCP workload identity target rejected: %v", err)
	}
	withStatic := base
	withStatic.TokenRef = "file:/run/secrets/gcp-token"
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{withStatic}}, true); err == nil ||
		!strings.Contains(err.Error(), "forbids static token_ref") {
		t.Fatalf("GCP workload identity with static fallback error = %v", err)
	}
	implicit := base
	implicit.GCPWorkloadIdentity = false
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{implicit}}, true); err == nil ||
		!strings.Contains(err.Error(), "token_ref") {
		t.Fatalf("implicit GCP workload identity target error = %v", err)
	}
}

func TestValidateSecretIntegrationsAzureFederatedIsExplicitAndRejectsStaticFallback(t *testing.T) {
	base := SecretSyncTargetConfig{
		TenantID: "11111111-1111-1111-1111-111111111111",
		ID:       "azure-federated", Type: "azure-key-vault",
		Endpoint: "https://payments.vault.azure.net", AzureWorkloadIdentity: true,
	}
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{base}}, true); err != nil {
		t.Fatalf("explicit Azure workload identity target rejected: %v", err)
	}
	withStatic := base
	withStatic.TokenRef = "file:/run/secrets/azure-token"
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{withStatic}}, true); err == nil ||
		!strings.Contains(err.Error(), "forbids static token_ref") {
		t.Fatalf("Azure workload identity with static fallback error = %v", err)
	}
	implicit := base
	implicit.AzureWorkloadIdentity = false
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{implicit}}, true); err == nil ||
		!strings.Contains(err.Error(), "token_ref") {
		t.Fatalf("implicit Azure workload identity target error = %v", err)
	}
	wrongProvider := base
	wrongProvider.Type = "gcp-secret-manager"
	wrongProvider.Project = "payments-production"
	if err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{wrongProvider}}, true); err == nil ||
		!strings.Contains(err.Error(), "only valid for azure-key-vault") {
		t.Fatalf("Azure workload identity on a non-Azure target error = %v", err)
	}
}

func TestValidateSecretIntegrationsFailsClosed(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	tests := []struct {
		name string
		cfg  SecretIntegrationsConfig
		on   bool
		want string
	}{
		{
			name: "API disabled", on: false, want: "require secrets.enable_api=true",
			cfg: SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{{TenantID: tenant, ID: "redis", Type: "redis", Addr: "redis:6379", AllowedRoles: []string{"read"}}}},
		},
		{
			name: "inline credential", on: true, want: "must use file:",
			cfg: SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{{TenantID: tenant, ID: "gcp", Type: "gcp-secret-manager", Endpoint: "https://example.test", Project: "p", TokenRef: "plaintext-token"}}},
		},
		{
			name: "relative credential file", on: true, want: "absolute path",
			cfg: SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{{TenantID: tenant, ID: "gcp", Type: "gcp-secret-manager", Endpoint: "https://example.test", Project: "p", TokenRef: "file:token"}}},
		},
		{
			name: "tenant duplicate", on: true, want: "duplicates tenant/id",
			cfg: SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{
				{TenantID: tenant, ID: "redis", Type: "redis", Addr: "one:6379", AllowedRoles: []string{"read"}},
				{TenantID: tenant, ID: "redis", Type: "redis", Addr: "two:6379", AllowedRoles: []string{"read"}},
			}},
		},
		{
			name: "unbound Kubernetes role", on: true, want: "role_bindings",
			cfg: SecretIntegrationsConfig{DynamicProviders: []DynamicSecretProviderConfig{{TenantID: tenant, ID: "k8s", Type: "kubernetes", Endpoint: "https://example.test", Namespace: "default", BearerTokenRef: "secret://k8s-token", AllowedRoles: []string{"read"}}}}, // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		},
		{
			name: "unsafe private endpoint policy", on: true, want: "requires private_egress_cidrs",
			cfg: SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{{TenantID: tenant, ID: "gcp", Type: "gcp-secret-manager", Endpoint: "http://127.0.0.1:8080", Project: "p", TokenRef: "secret://gcp-token", AllowPrivate: true}}}, // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		},
		{
			name: "Terraform invalid category", on: true, want: "variable_category must be terraform or env",
			cfg: SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{{TenantID: tenant, ID: "tfc", Type: "terraform-cloud-opentofu", Endpoint: "https://app.terraform.io", WorkspaceID: "ws-production", VariableCategory: "secret", TokenRef: "secret://tfc-token"}}}, // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		},
		{
			name: "Terraform environment HCL", on: true, want: "hcl=true is valid only for terraform variables",
			cfg: SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{{TenantID: tenant, ID: "tfc", Type: "terraform-cloud-opentofu", Endpoint: "https://app.terraform.io", WorkspaceID: "ws-production", VariableCategory: "env", HCL: true, TokenRef: "secret://tfc-token"}}}, // #nosec G101 -- fabricated fixture credential/identifier; the test needs the shape, no value is real (CWE-798)
		},
		{
			name: "Vault traversal path", on: true, want: "path_prefix must not contain dot path components",
			cfg: SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{{TenantID: tenant, ID: "vault", Type: "vault-kv-v2", Endpoint: "https://vault.example.test", Mount: "secret", PathPrefix: "apps/../admin", TokenRef: "secret://vault-token"}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSecretIntegrations(tt.cfg, tt.on)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestValidateSecretIntegrationsRequiresHTTPSExceptExplicitLoopback(t *testing.T) {
	const tenant = "11111111-1111-1111-1111-111111111111"
	base := func(endpoint string) SecretSyncTargetConfig {
		return SecretSyncTargetConfig{
			TenantID: tenant, ID: "generic", Type: "generic-ci-json",
			Endpoint: endpoint, Provider: "build",
		}
	}
	tests := []struct {
		name string
		edit func(*SecretSyncTargetConfig)
		ok   bool
	}{
		{name: "HTTPS production", edit: func(c *SecretSyncTargetConfig) { c.Endpoint = "https://sync.example.test" }, ok: true},
		{name: "public HTTP with insecure opt in", edit: func(c *SecretSyncTargetConfig) {
			c.Endpoint = "http://198.51.100.10:8080"
			c.AllowInsecureLoopback = true
		}},
		{name: "private HTTP with both egress knobs", edit: func(c *SecretSyncTargetConfig) {
			c.Endpoint = "http://10.1.2.3:8080"
			c.AllowPrivate = true
			c.PrivateEgressCIDRs = []string{"10.0.0.0/8"}
			c.AllowInsecureLoopback = true
		}},
		{name: "allow private alone cannot enable loopback HTTP", edit: func(c *SecretSyncTargetConfig) {
			c.Endpoint = "http://127.0.0.1:8080"
			c.AllowPrivate = true
			c.PrivateEgressCIDRs = []string{"127.0.0.0/8"}
		}},
		{name: "loopback HTTP explicit opt in", edit: func(c *SecretSyncTargetConfig) {
			c.Endpoint = "http://127.0.0.1:8080"
			c.AllowInsecureLoopback = true
		}, ok: true},
		{name: "localhost HTTP explicit opt in", edit: func(c *SecretSyncTargetConfig) {
			c.Endpoint = "http://localhost:8080"
			c.AllowInsecureLoopback = true
		}, ok: true},
		{name: "unused insecure opt in", edit: func(c *SecretSyncTargetConfig) {
			c.Endpoint = "https://sync.example.test"
			c.AllowInsecureLoopback = true
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := base("https://sync.example.test")
			tt.edit(&entry)
			err := ValidateSecretIntegrations(SecretIntegrationsConfig{SyncTargets: []SecretSyncTargetConfig{entry}}, true)
			if (err == nil) != tt.ok {
				t.Fatalf("ValidateSecretIntegrations() = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}
