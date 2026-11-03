// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/dynsecret"
)

// The A239 dynamic-credential provider library's backend openers: each reads
// its provider's credentials through the opener, builds the guarded client it
// needs, and hands the backend its own sealed copies (split from
// secret_integrations.go to keep that served file within its size budget).

// openConfiguredTOTPBackend reads the seed into a code generator that keeps
// its own sealed copy; nothing leaves the control plane but codes (A239).
func openConfiguredTOTPBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	seed, err := o.resolve(cfg.SeedRef)
	if err != nil {
		return o.fail(err)
	}
	period := 30 * time.Second
	if value := strings.TrimSpace(cfg.Period); value != "" {
		if period, err = time.ParseDuration(value); err != nil {
			return o.fail(fmt.Errorf("server: totp period: %w", err))
		}
	}
	backend, err := dynsecret.NewTOTPBackend(dynsecret.TOTPConfig{SeedBase32: seed, Digits: cfg.Digits, Period: period, Algorithm: cfg.Algorithm})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredOAuthBackend reads the client secret into a token client that
// keeps its own sealed copy and calls the token and revocation endpoints through
// the SSRF-guarded HTTP client (A239).
func openConfiguredOAuthBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	clientSecret, err := o.resolve(cfg.ClientSecretRef)
	if err != nil {
		return o.fail(err)
	}
	client, err := secretIntegrationHTTPClient(cfg.Endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewOAuthClientCredentialsBackend(dynsecret.OAuthClientCredentialsConfig{
		TokenURL: cfg.Endpoint, RevocationURL: cfg.RevocationEndpoint, ClientID: cfg.ClientID, ClientSecret: clientSecret,
		RoleScopes: cfg.RoleBindings, MaxLifetime: o.provider.maxTTL, AllowInsecureLoopback: cfg.AllowInsecureLoopback,
		HTTPClient: client,
	})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredClickHouseBackend reads the administrator password into a
// backend that keeps its own sealed copy and speaks ClickHouse's HTTP interface
// through the SSRF-guarded client (A239).
func openConfiguredClickHouseBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	password, err := o.resolve(cfg.PasswordRef)
	if err != nil {
		return o.fail(err)
	}
	client, err := secretIntegrationHTTPClient(cfg.Endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewClickHouseBackend(dynsecret.ClickHouseConfig{
		Endpoint: cfg.Endpoint, AdminUser: cfg.AdminUser, AdminPassword: password, RoleBindings: cfg.RoleBindings,
		UsernamePrefix: cfg.UsernamePrefix, MaxLifetime: o.provider.maxTTL, AllowInsecureLoopback: cfg.AllowInsecureLoopback,
		HTTPClient: client,
	})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredElasticsearchBackend reads the administrator password into a
// backend that keeps its own sealed copy and calls the security API through the
// SSRF-guarded client (A239).
func openConfiguredElasticsearchBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	password, err := o.resolve(cfg.PasswordRef)
	if err != nil {
		return o.fail(err)
	}
	client, err := secretIntegrationHTTPClient(cfg.Endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewElasticsearchBackend(dynsecret.ElasticsearchConfig{
		Endpoint: cfg.Endpoint, AdminUser: cfg.AdminUser, AdminPassword: password, RoleBindings: cfg.RoleBindings,
		MaxLifetime: o.provider.maxTTL, AllowInsecureLoopback: cfg.AllowInsecureLoopback, HTTPClient: client,
	})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredRabbitMQBackend reads the administrator password into a backend
// that keeps its own sealed copy and calls the management API through the
// SSRF-guarded client (A239).
func openConfiguredRabbitMQBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	password, err := o.resolve(cfg.PasswordRef)
	if err != nil {
		return o.fail(err)
	}
	client, err := secretIntegrationHTTPClient(cfg.Endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewRabbitMQBackend(dynsecret.RabbitMQConfig{
		Endpoint: cfg.Endpoint, AdminUser: cfg.AdminUser, AdminPassword: password, RoleBindings: cfg.RoleBindings,
		UsernamePrefix: cfg.UsernamePrefix, AllowInsecureLoopback: cfg.AllowInsecureLoopback, HTTPClient: client,
	})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredTailscaleBackend reads the API token into a backend that keeps
// its own sealed copy and calls the Tailscale API through the SSRF-guarded
// client (A239).
func openConfiguredTailscaleBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	token, err := o.resolve(cfg.BearerTokenRef)
	if err != nil {
		return o.fail(err)
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://api.tailscale.com"
	}
	client, err := secretIntegrationHTTPClient(endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewTailscaleBackend(dynsecret.TailscaleConfig{
		Endpoint: endpoint, Tailnet: cfg.Tailnet, APIToken: token, RoleBindings: cfg.RoleBindings,
		MaxLifetime: o.provider.maxTTL, AllowInsecureLoopback: cfg.AllowInsecureLoopback, HTTPClient: client,
	})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredMongoDBAtlasBackend reads the service account's secret into a
// backend that keeps its own sealed copy and calls the Atlas Admin API through
// the SSRF-guarded client (A239).
func openConfiguredMongoDBAtlasBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	clientSecret, err := o.resolve(cfg.ClientSecretRef)
	if err != nil {
		return o.fail(err)
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://cloud.mongodb.com"
	}
	client, err := secretIntegrationHTTPClient(endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewMongoDBAtlasBackend(dynsecret.MongoDBAtlasConfig{
		Endpoint: endpoint, GroupID: cfg.Project, ClientID: cfg.ClientID, ClientSecret: clientSecret,
		RoleBindings: cfg.RoleBindings, UsernamePrefix: cfg.UsernamePrefix, MaxLifetime: o.provider.maxTTL,
		AllowInsecureLoopback: cfg.AllowInsecureLoopback, HTTPClient: client,
	})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredKafkaBackend reads the administrator's SCRAM password (and a
// private CA) into a backend that keeps its own sealed copy and reaches the
// brokers over verified TLS, or the allowed plaintext (A239).
func openConfiguredKafkaBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	password, err := o.resolve(cfg.PasswordRef)
	if err != nil {
		return o.fail(err)
	}
	var caPEM []byte
	if cfg.TLSCARef != "" {
		if caPEM, err = o.resolve(cfg.TLSCARef); err != nil {
			return o.fail(err)
		}
	}
	backend, err := dynsecret.NewKafkaBackend(dynsecret.KafkaConfig{
		Addr: cfg.Addr, TLSServerName: cfg.TLSServerName, TLSCAPEM: caPEM, AllowPlaintext: cfg.AllowPlaintext,
		AdminUser: cfg.AdminUser, AdminPassword: password, RoleBindings: cfg.RoleBindings, UsernamePrefix: cfg.UsernamePrefix,
	})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredCassandraBackend reads the administrator's password (and a
// private CA) into a backend that keeps its own sealed copy and reaches the one
// configured node over verified TLS, or the allowed plaintext (A239).
func openConfiguredCassandraBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	password, err := o.resolve(cfg.PasswordRef)
	if err != nil {
		return o.fail(err)
	}
	var caPEM []byte
	if cfg.TLSCARef != "" {
		if caPEM, err = o.resolve(cfg.TLSCARef); err != nil {
			return o.fail(err)
		}
	}
	backend, err := dynsecret.NewCassandraBackend(dynsecret.CassandraConfig{
		Addr: cfg.Addr, TLSServerName: cfg.TLSServerName, TLSCAPEM: caPEM, AllowPlaintext: cfg.AllowPlaintext,
		AdminUser: cfg.AdminUser, AdminPassword: password, RoleBindings: cfg.RoleBindings, UsernamePrefix: cfg.UsernamePrefix,
	})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredCouchbaseBackend reads the administrator password into a backend
// that keeps its own sealed copy and calls the management REST API through the
// SSRF-guarded client (A239).
func openConfiguredCouchbaseBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	password, err := o.resolve(cfg.PasswordRef)
	if err != nil {
		return o.fail(err)
	}
	client, err := secretIntegrationHTTPClient(cfg.Endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewCouchbaseBackend(dynsecret.CouchbaseConfig{
		Endpoint: cfg.Endpoint, AdminUser: cfg.AdminUser, AdminPassword: password, RoleBindings: cfg.RoleBindings,
		UsernamePrefix: cfg.UsernamePrefix, AllowInsecureLoopback: cfg.AllowInsecureLoopback, HTTPClient: client,
	})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredMilvusBackend reads the administrator password into a backend
// that keeps its own sealed copy and calls the RESTful API through the
// SSRF-guarded client (A239).
func openConfiguredMilvusBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	password, err := o.resolve(cfg.PasswordRef)
	if err != nil {
		return o.fail(err)
	}
	client, err := secretIntegrationHTTPClient(cfg.Endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewMilvusBackend(dynsecret.MilvusConfig{
		Endpoint: cfg.Endpoint, AdminUser: cfg.AdminUser, AdminPassword: password, RoleBindings: cfg.RoleBindings,
		UsernamePrefix: cfg.UsernamePrefix, AllowInsecureLoopback: cfg.AllowInsecureLoopback, HTTPClient: client,
	})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredGitHubAppBackend reads the app's private key into a backend that
// keeps its own sealed copy, signs each token request's app JWT through the
// crypto boundary, and calls the API through the SSRF-guarded client (A239).
func openConfiguredGitHubAppBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	privateKey, err := o.resolve(cfg.PrivateKeyRef)
	if err != nil {
		return o.fail(err)
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://api.github.com"
	}
	client, err := secretIntegrationHTTPClient(endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewGitHubAppBackend(dynsecret.GitHubAppConfig{
		Endpoint: endpoint, ClientID: cfg.ClientID, PrivateKey: privateKey, InstallationID: cfg.InstallationID,
		RoleBindings: cfg.RoleBindings, MaxLifetime: o.provider.maxTTL, AllowInsecureLoopback: cfg.AllowInsecureLoopback, HTTPClient: client,
	})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredSnowflakeBackend reads the administrator's private key into a
// backend that keeps its own sealed copy, signs each SQL API request's key-pair
// JWT through the crypto boundary, and calls the API through the SSRF-guarded
// client (A239).
func openConfiguredSnowflakeBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	privateKey, err := o.resolve(cfg.PrivateKeyRef)
	if err != nil {
		return o.fail(err)
	}
	client, err := secretIntegrationHTTPClient(cfg.Endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewSnowflakeBackend(dynsecret.SnowflakeConfig{
		Endpoint: cfg.Endpoint, Account: cfg.Account, AdminUser: cfg.AdminUser, AdminPrivateKey: privateKey,
		RoleBindings: cfg.RoleBindings, UsernamePrefix: cfg.UsernamePrefix, MaxLifetime: o.provider.maxTTL,
		AllowInsecureLoopback: cfg.AllowInsecureLoopback, HTTPClient: client,
	})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredAWSCacheBackend reads the AWS access key into a backend that
// keeps its own sealed copy and signs ElastiCache Query or MemoryDB JSON API
// calls (SigV4) through the SSRF-guarded client (A239).
func openConfiguredAWSCacheBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	secretKey, err := o.resolve(cfg.SecretAccessRef)
	if err != nil {
		return o.fail(err)
	}
	var session []byte
	if cfg.SessionTokenRef != "" {
		if session, err = o.resolve(cfg.SessionTokenRef); err != nil {
			return o.fail(err)
		}
	}
	service := dynsecret.AWSElastiCache
	endpoint := cfg.Endpoint
	if cfg.Type == "aws-memorydb" {
		service = dynsecret.AWSMemoryDB
		if endpoint == "" {
			endpoint = "https://memory-db." + cfg.Region + ".amazonaws.com"
		}
	} else if endpoint == "" {
		endpoint = "https://elasticache." + cfg.Region + ".amazonaws.com"
	}
	client, err := secretIntegrationHTTPClient(endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewAWSCacheUsersBackend(dynsecret.AWSCacheUsersConfig{
		Service: service, Endpoint: endpoint, Region: cfg.Region, AccessKeyID: cfg.AccessKeyID, SecretAccessKey: secretKey,
		SessionToken: session, UserGroup: cfg.UserGroup, Engine: cfg.Engine, RolePolicies: cfg.RedisACLRoles,
		UsernamePrefix: cfg.UsernamePrefix, HTTPClient: client,
	})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredAPIConnectBackend reads the platform client secret and API key
// into a backend that keeps its own sealed copies and calls the platform API
// through the SSRF-guarded client (A239).
func openConfiguredAPIConnectBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	clientSecret, err := o.resolve(cfg.ClientSecretRef)
	if err != nil {
		return o.fail(err)
	}
	apiKey, err := o.resolve(cfg.APIKeyRef)
	if err != nil {
		return o.fail(err)
	}
	client, err := secretIntegrationHTTPClient(cfg.Endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewAPIConnectBackend(dynsecret.APIConnectConfig{
		Endpoint: cfg.Endpoint, ClientID: cfg.ClientID, ClientSecret: clientSecret, APIKey: apiKey, RoleBindings: cfg.RoleBindings,
		UsernamePrefix: cfg.UsernamePrefix, AllowInsecureLoopback: cfg.AllowInsecureLoopback, HTTPClient: client,
	})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredAuth0Backend reads the management client secret into a backend
// that keeps its own sealed copy and calls the tenant through the SSRF-guarded
// client (A240).
func openConfiguredAuth0Backend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	clientSecret, err := o.resolve(cfg.ClientSecretRef)
	if err != nil {
		return o.fail(err)
	}
	client, err := secretIntegrationHTTPClient(cfg.Endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewAuth0Backend(dynsecret.Auth0Config{
		Endpoint: cfg.Endpoint, ClientID: cfg.ClientID, ClientSecret: clientSecret, RoleBindings: cfg.RoleBindings,
		AllowInsecureLoopback: cfg.AllowInsecureLoopback, HTTPClient: client,
	})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredUnixBackend reads the administrator's private key into a
// backend that keeps its own sealed copy and runs only chpasswd on the pinned
// host (A240).
func openConfiguredUnixBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	adminKey, err := o.resolve(cfg.PrivateKeyRef)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewUnixAccountsBackend(dynsecret.UnixAccountsConfig{
		Address: cfg.Addr, AdminUser: cfg.AdminUser, AdminKey: adminKey, HostKeyFingerprint: cfg.HostKeyFingerprint,
		Sudo: cfg.Sudo, RoleAccounts: cfg.RoleBindings, RotationAccounts: o.provider.rotationAccountPairs(),
	})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredOpenAIBackend reads the organization admin key into a backend
// that keeps its own sealed copy and calls the API through the SSRF-guarded
// client (A240).
func openConfiguredOpenAIBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	adminKey, err := o.resolve(cfg.APIKeyRef)
	if err != nil {
		return o.fail(err)
	}
	client, err := secretIntegrationHTTPClient(cfg.Endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewOpenAIBackend(dynsecret.OpenAIConfig{
		Endpoint: cfg.Endpoint, AdminKey: adminKey, RoleBindings: cfg.RoleBindings,
		UsernamePrefix: cfg.UsernamePrefix, AllowInsecureLoopback: cfg.AllowInsecureLoopback, HTTPClient: client,
	})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}

// openConfiguredDatadogBackend reads the administrator's API and application
// keys into a backend that keeps its own sealed copies and calls the site's
// API through the SSRF-guarded client (A240).
func openConfiguredDatadogBackend(o *configuredDynamicBackendOpener) (requestDynamicBackend, func(), error) {
	cfg := o.provider.cfg
	apiKey, err := o.resolve(cfg.APIKeyRef)
	if err != nil {
		return o.fail(err)
	}
	applicationKey, err := o.resolve(cfg.ApplicationKeyRef)
	if err != nil {
		return o.fail(err)
	}
	client, err := secretIntegrationHTTPClient(cfg.Endpoint, cfg.AllowPrivate, cfg.AllowInsecureLoopback, cfg.PrivateEgressCIDRs, o.provider.guard)
	if err != nil {
		return o.fail(err)
	}
	backend, err := dynsecret.NewDatadogBackend(dynsecret.DatadogConfig{
		Endpoint: cfg.Endpoint, APIKey: apiKey, ApplicationKey: applicationKey, RoleBindings: cfg.RoleBindings,
		UsernamePrefix: cfg.UsernamePrefix, AllowInsecureLoopback: cfg.AllowInsecureLoopback, HTTPClient: client,
	})
	if err != nil {
		return o.fail(err)
	}
	return backend, o.closeWith(backend, nil), nil
}
