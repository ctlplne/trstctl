//go:build trstctl_dodproof

// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/app"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/secrettext"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/tools/dodcensus/proof"
)

func TestDODPostgresDataDirUsesContainerOwnedScratch(t *testing.T) {
	t.Setenv(dodRuntimeTempRootEnv, dodRuntimeTempRoot)
	dir, cleanup, err := dodPostgresDataDir("/dod-tmp/caller/postgres")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(dir, "/tmp/trstctl-dod-postgres-") {
		cleanup()
		t.Fatalf("DoD Postgres data dir = %q, want private /tmp child", dir)
	}
	info, err := os.Stat(dir)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		cleanup()
		t.Fatalf("DoD Postgres data dir mode = %04o, want owner-only", info.Mode().Perm())
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("DoD Postgres cleanup left %s: %v", dir, err)
	}
}

func TestDODPostgresDataDirPreservesCallerPathOutsideRunner(t *testing.T) {
	t.Setenv(dodRuntimeTempRootEnv, "")
	want := filepath.Join(t.TempDir(), "postgres")
	got, cleanup, err := dodPostgresDataDir(want)
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if got != want {
		t.Fatalf("ordinary DoD Postgres data dir = %q, want %q", got, want)
	}
}

const dodSecretIntegrationTenant = "d0d00000-0000-4000-8000-000000000301"

type dodSecretIntegrationTarget struct {
	entryID string
	id      string
	kind    string
}

type dodDynamicLeaseWire struct {
	ID         string         `json:"id"`
	Provider   string         `json:"provider"`
	State      string         `json:"state"`
	Credential dodSecretBytes `json:"credential"`
}

// TestDODSecretIntegrationsProductionAssembly is shared by the registry and all eight
// granular dynamic-secret census rows. It passes untouched buildRunDeps output
// to Build and proves independently usable, rotated, then revoked credentials.
func TestDODSecretIntegrationsProductionAssembly(t *testing.T) {
	only := dodRuntimeSelection(t,
		"dynamic_secret.registry", "dynamic_secret.postgresql", "dynamic_secret.mysql",
		"dynamic_secret.mongodb", "dynamic_secret.aws_iam", "dynamic_secret.gcp_iam",
		"dynamic_secret.azure_entra", "dynamic_secret.kubernetes", "dynamic_secret.redis",
	)
	if only == "" {
		dodRunAllDynamicSecretProductionAssembly(t)
		return
	}
	if only == "dynamic_secret.registry" {
		external := proof.StartCommand(t, "dynamic_secret.registry")
		dodRunFocusedDynamicSecret(t, "dynamic_secret.registry", external, dodSecretIntegrationTarget{"dynamic_secret.registry", "registry", "postgresql"})
		return
	}
	if only == "dynamic_secret.postgresql" {
		external := proof.StartCommand(t, "dynamic_secret.postgresql")
		dodRunFocusedDynamicSecret(t, "dynamic_secret.postgresql", external, dodSecretIntegrationTarget{"dynamic_secret.postgresql", "postgresql", "postgresql"})
		return
	}
	if only == "dynamic_secret.mysql" {
		external := proof.StartCommand(t, "dynamic_secret.mysql")
		dodRunFocusedDynamicSecret(t, "dynamic_secret.mysql", external, dodSecretIntegrationTarget{"dynamic_secret.mysql", "mysql", "mysql"})
		return
	}
	if only == "dynamic_secret.mongodb" {
		external := proof.StartCommand(t, "dynamic_secret.mongodb")
		dodRunFocusedDynamicSecret(t, "dynamic_secret.mongodb", external, dodSecretIntegrationTarget{"dynamic_secret.mongodb", "mongodb", "mongodb"})
		return
	}
	if only == "dynamic_secret.aws_iam" {
		external := proof.StartCommand(t, "dynamic_secret.aws_iam")
		dodRunFocusedDynamicSecret(t, "dynamic_secret.aws_iam", external, dodSecretIntegrationTarget{"dynamic_secret.aws_iam", "aws-iam", "aws-iam"})
		return
	}
	if only == "dynamic_secret.gcp_iam" {
		external := proof.StartCommand(t, "dynamic_secret.gcp_iam")
		dodRunFocusedDynamicSecret(t, "dynamic_secret.gcp_iam", external, dodSecretIntegrationTarget{"dynamic_secret.gcp_iam", "gcp-iam", "gcp-iam"})
		return
	}
	if only == "dynamic_secret.azure_entra" {
		external := proof.StartCommand(t, "dynamic_secret.azure_entra")
		dodRunFocusedDynamicSecret(t, "dynamic_secret.azure_entra", external, dodSecretIntegrationTarget{"dynamic_secret.azure_entra", "azure-entra", "azure-entra"})
		return
	}
	if only == "dynamic_secret.kubernetes" {
		external := proof.StartCommand(t, "dynamic_secret.kubernetes")
		dodRunFocusedDynamicSecret(t, "dynamic_secret.kubernetes", external, dodSecretIntegrationTarget{"dynamic_secret.kubernetes", "kubernetes", "kubernetes"})
		return
	}
	external := proof.StartCommand(t, "dynamic_secret.redis")
	dodRunFocusedDynamicSecret(t, "dynamic_secret.redis", external, dodSecretIntegrationTarget{"dynamic_secret.redis", "redis", "redis"})
}

// TestDODSecretSyncProductionAssembly is shared by the registry, all eight
// granular secret-sync census rows, and the two provider-native residual cards.
// It passes untouched buildRunDeps output to Build and proves authenticated
// external write/readback outside the process.
func TestDODSecretSyncProductionAssembly(t *testing.T) {
	only := dodRuntimeSelection(t,
		"secret_sync.registry", "secret_sync.aws_secrets_manager", "secret_sync.gcp_secret_manager",
		"secret_sync.azure_key_vault", "secret_sync.github_actions", "secret_sync.gitlab_ci",
		"secret_sync.vercel", "secret_sync.generic_ci_json", "secret_sync.kubernetes_secrets",
		"secrets_residuals.terraform_opentofu_native_sync", "secrets_residuals.vault_kv_outbound_sync",
	)
	if only == "" {
		dodRunAllSecretSyncProductionAssembly(t)
		return
	}
	if only == "secret_sync.registry" {
		external := proof.StartCommand(t, "secret_sync.registry")
		dodRunFocusedSecretSync(t, "secret_sync.registry", external, dodSecretIntegrationTarget{"secret_sync.registry", "registry", "generic"})
		return
	}
	if only == "secret_sync.aws_secrets_manager" {
		external := proof.StartCommand(t, "secret_sync.aws_secrets_manager")
		dodRunFocusedSecretSync(t, "secret_sync.aws_secrets_manager", external, dodSecretIntegrationTarget{"secret_sync.aws_secrets_manager", "aws-secrets-manager", "aws"})
		return
	}
	if only == "secret_sync.gcp_secret_manager" {
		external := proof.StartCommand(t, "secret_sync.gcp_secret_manager")
		dodRunFocusedSecretSync(t, "secret_sync.gcp_secret_manager", external, dodSecretIntegrationTarget{"secret_sync.gcp_secret_manager", "gcp-secret-manager", "gcp"})
		return
	}
	if only == "secret_sync.azure_key_vault" {
		external := proof.StartCommand(t, "secret_sync.azure_key_vault")
		dodRunFocusedSecretSync(t, "secret_sync.azure_key_vault", external, dodSecretIntegrationTarget{"secret_sync.azure_key_vault", "azure-key-vault", "azure"})
		return
	}
	if only == "secret_sync.github_actions" {
		external := proof.StartCommand(t, "secret_sync.github_actions")
		dodRunFocusedSecretSync(t, "secret_sync.github_actions", external, dodSecretIntegrationTarget{"secret_sync.github_actions", "github-actions", "github"})
		return
	}
	if only == "secret_sync.gitlab_ci" {
		external := proof.StartCommand(t, "secret_sync.gitlab_ci")
		dodRunFocusedSecretSync(t, "secret_sync.gitlab_ci", external, dodSecretIntegrationTarget{"secret_sync.gitlab_ci", "gitlab-ci", "gitlab"})
		return
	}
	if only == "secret_sync.vercel" {
		external := proof.StartCommand(t, "secret_sync.vercel")
		dodRunFocusedSecretSync(t, "secret_sync.vercel", external, dodSecretIntegrationTarget{"secret_sync.vercel", "vercel", "vercel"})
		return
	}
	if only == "secret_sync.generic_ci_json" {
		external := proof.StartCommand(t, "secret_sync.generic_ci_json")
		dodRunFocusedSecretSync(t, "secret_sync.generic_ci_json", external, dodSecretIntegrationTarget{"secret_sync.generic_ci_json", "generic-ci-json", "generic"})
		return
	}
	if only == "secret_sync.kubernetes_secrets" {
		external := proof.StartCommand(t, "secret_sync.kubernetes_secrets")
		dodRunFocusedSecretSync(t, "secret_sync.kubernetes_secrets", external, dodSecretIntegrationTarget{"secret_sync.kubernetes_secrets", "kubernetes-secrets", "kubernetes"})
		return
	}
	if only == "secrets_residuals.terraform_opentofu_native_sync" {
		external := proof.StartCommand(t, "secrets_residuals.terraform_opentofu_native_sync")
		dodRunFocusedSecretSync(t, only, external, dodSecretIntegrationTarget{only, "terraform-cloud-opentofu", "terraform"})
		return
	}
	external := proof.StartCommand(t, "secrets_residuals.vault_kv_outbound_sync")
	dodRunFocusedSecretSync(t, only, external, dodSecretIntegrationTarget{only, "vault-kv-v2", "vault"})
}

func dodRunAllDynamicSecretProductionAssembly(t *testing.T) {
	// Each real database is a separate bulkhead. Wait for its native health
	// proof before starting the next one so a full-family run cannot turn a
	// Docker resource spike into nine false product failures.
	dynamicRegistry, registryDB := dodStartDatabaseSecretSubstrate(t, "dynamic_secret.registry")
	dynamicPostgres, postgresDB := dodStartDatabaseSecretSubstrate(t, "dynamic_secret.postgresql")
	dynamicMySQL, mysqlDB := dodStartDatabaseSecretSubstrate(t, "dynamic_secret.mysql")
	dynamicMongo, mongoDB := dodStartDatabaseSecretSubstrate(t, "dynamic_secret.mongodb")
	dynamicRedis, redisDB := dodStartDatabaseSecretSubstrate(t, "dynamic_secret.redis")
	dynamicAWS := proof.StartCommand(t, "dynamic_secret.aws_iam")
	dynamicGCP := proof.StartCommand(t, "dynamic_secret.gcp_iam")
	dynamicAzure := proof.StartCommand(t, "dynamic_secret.azure_entra")
	dynamicKubernetes := proof.StartCommand(t, "dynamic_secret.kubernetes")

	secretDir := t.TempDir()
	fileRef := func(name string, value []byte) string { return dodSecretIntegrationFile(t, secretDir, name, value) }
	network := func() (bool, []string) { return true, []string{"127.0.0.0/8"} }
	private, cidrs := network()

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Secrets.EnableAPI = true
	cfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "secrets-kek.bin")
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	cfg.CA.CertFile = filepath.Join(t.TempDir(), "issuing-ca.pem")
	dynamicAWSEndpoint := dodParentSubstrateLoopbackBridge(t, dynamicAWS.Endpoint())
	dynamicGCPEndpoint := dodParentSubstrateLoopbackBridge(t, dynamicGCP.Endpoint())
	dynamicAzureEndpoint := dodParentSubstrateLoopbackBridge(t, dynamicAzure.Endpoint())
	dynamicKubernetesEndpoint := dodParentSubstrateLoopbackBridge(t, dynamicKubernetes.Endpoint())
	cfg.SecretIntegrations.DynamicProviders = []config.DynamicSecretProviderConfig{
		{TenantID: dodSecretIntegrationTenant, ID: "registry", Type: "postgresql", AdminDSNRef: fileRef("registry-postgres-dsn", []byte(registryDB.AdminDSN)), Database: registryDB.Database, AllowedRoles: []string{"reader"}, MaxTTL: "15m", UsernamePrefix: "dod_registry"},
		{TenantID: dodSecretIntegrationTenant, ID: "postgresql", Type: "postgresql", AdminDSNRef: fileRef("postgres-dsn", []byte(postgresDB.AdminDSN)), Database: postgresDB.Database, AllowedRoles: []string{"reader"}, MaxTTL: "15m", UsernamePrefix: "dod_postgres"},
		{TenantID: dodSecretIntegrationTenant, ID: "mysql", Type: "mysql", AdminDSNRef: fileRef("mysql-dsn", []byte(mysqlDB.AdminDSN)), Database: mysqlDB.Database, Addr: mysqlDB.Addr, AccountHost: "%", AllowedRoles: []string{"reader"}, MaxTTL: "15m", UsernamePrefix: "dod_mysql"},
		{TenantID: dodSecretIntegrationTenant, ID: "mongodb", Type: "mongodb", AdminDSNRef: fileRef("mongo-dsn", []byte(mongoDB.AdminDSN)), Database: mongoDB.Database, AllowedRoles: []string{"reader"}, MaxTTL: "15m", UsernamePrefix: "dod_mongo"},
		{TenantID: dodSecretIntegrationTenant, ID: "aws-iam", Type: "aws-iam", Endpoint: dynamicAWSEndpoint, Region: "us-east-1", AccessKeyID: "AKIADODADMIN", SecretAccessRef: fileRef("aws-admin-secret", []byte("dod-aws-admin-secret")), AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "arn:aws:iam::123456789012:policy/DODReadOnly"}, MaxTTL: "15m", AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs, UsernamePrefix: "dod_aws"},
		{TenantID: dodSecretIntegrationTenant, ID: "gcp-iam", Type: "gcp-iam", Endpoint: dynamicGCPEndpoint, Project: "p", ServiceAccount: "dyn@p.iam.gserviceaccount.com", BearerTokenRef: fileRef("gcp-admin-token", []byte("dod-gcp-admin-token")), AllowedRoles: []string{"reader"}, MaxTTL: "15m", AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs, UsernamePrefix: "dod-gcp"},
		{TenantID: dodSecretIntegrationTenant, ID: "azure-entra", Type: "azure-entra", Endpoint: dynamicAzureEndpoint, ApplicationObject: "app-obj", ApplicationClient: "dod-client", AzureTenant: "dod-tenant", BearerTokenRef: fileRef("azure-admin-token", []byte("dod-azure-admin-token")), AllowedRoles: []string{"reader"}, MaxTTL: "15m", AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs, UsernamePrefix: "dod-azure"},
		{TenantID: dodSecretIntegrationTenant, ID: "kubernetes", Type: "kubernetes", Endpoint: dynamicKubernetesEndpoint, Namespace: "apps", BearerTokenRef: fileRef("kubernetes-admin-token", []byte("dod-k8s-admin-token")), AllowedRoles: []string{"reader"}, RoleBindings: map[string]string{"reader": "Role/dod-reader"}, MaxTTL: "15m", AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs, UsernamePrefix: "dod-k8s"},
		{TenantID: dodSecretIntegrationTenant, ID: "redis", Type: "redis", Addr: redisDB.Addr, PasswordRef: fileRef("redis-admin-password", []byte(redisDB.Password)), AllowedRoles: []string{"reader"}, MaxTTL: "15m", UsernamePrefix: "dod_redis"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("secret integration production config: %v", err)
	}

	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatal(err)
	}
	dodRegisterSecretIntegrationTenant(t, ctx, log, st)
	runSecrets, err := loadRunSecrets(cfg)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	t.Cleanup(runSecrets.Close)
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	signer := dodStartAuthorizedSoftwareSignerProcess(t, t.TempDir())
	deps, err := buildRunDeps(ctx, cfg, st, log, signer, runSecrets, slog.New(slog.NewTextHandler(io.Discard, nil)), guard)
	if err != nil {
		_ = log.Close()
		t.Fatalf("production buildRunDeps: %v", err)
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		_ = log.Close()
		t.Fatalf("Build production deps: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	dynamicDeliveryErrorClass := dodCaptureDynamicDeliveryErrorClass(t, srv)
	dodStartSecretIntegrationDispatcher(t, srv)
	token := dodSecretIntegrationToken(t, st)

	dodProveDynamicSecret(t, "dynamic_secret.registry", dynamicRegistry, srv, st, token, dynamicDeliveryErrorClass, dodSecretIntegrationTarget{"dynamic_secret.registry", "registry", "postgresql"})
	dodProveDynamicSecret(t, "dynamic_secret.postgresql", dynamicPostgres, srv, st, token, dynamicDeliveryErrorClass, dodSecretIntegrationTarget{"dynamic_secret.postgresql", "postgresql", "postgresql"})
	dodProveDynamicSecret(t, "dynamic_secret.mysql", dynamicMySQL, srv, st, token, dynamicDeliveryErrorClass, dodSecretIntegrationTarget{"dynamic_secret.mysql", "mysql", "mysql"})
	dodProveDynamicSecret(t, "dynamic_secret.mongodb", dynamicMongo, srv, st, token, dynamicDeliveryErrorClass, dodSecretIntegrationTarget{"dynamic_secret.mongodb", "mongodb", "mongodb"})
	dodProveDynamicSecret(t, "dynamic_secret.aws_iam", dynamicAWS, srv, st, token, dynamicDeliveryErrorClass, dodSecretIntegrationTarget{"dynamic_secret.aws_iam", "aws-iam", "aws-iam"})
	dodProveDynamicSecret(t, "dynamic_secret.gcp_iam", dynamicGCP, srv, st, token, dynamicDeliveryErrorClass, dodSecretIntegrationTarget{"dynamic_secret.gcp_iam", "gcp-iam", "gcp-iam"})
	dodProveDynamicSecret(t, "dynamic_secret.azure_entra", dynamicAzure, srv, st, token, dynamicDeliveryErrorClass, dodSecretIntegrationTarget{"dynamic_secret.azure_entra", "azure-entra", "azure-entra"})
	dodProveDynamicSecret(t, "dynamic_secret.kubernetes", dynamicKubernetes, srv, st, token, dynamicDeliveryErrorClass, dodSecretIntegrationTarget{"dynamic_secret.kubernetes", "kubernetes", "kubernetes"})
	dodProveDynamicSecret(t, "dynamic_secret.redis", dynamicRedis, srv, st, token, dynamicDeliveryErrorClass, dodSecretIntegrationTarget{"dynamic_secret.redis", "redis", "redis"})
}

func dodRunFocusedDynamicSecret(t *testing.T, entryID string, external *proof.ExternalSubstrate, target dodSecretIntegrationTarget) {
	t.Helper()
	secretDir := t.TempDir()
	fileRef := func(name string, value []byte) string { return dodSecretIntegrationFile(t, secretDir, name, value) }
	private, cidrs := true, []string{"127.0.0.0/8"}

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Secrets.EnableAPI = true
	cfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "secrets-kek.bin")
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	cfg.CA.CertFile = filepath.Join(t.TempDir(), "issuing-ca.pem")
	var provider config.DynamicSecretProviderConfig
	switch entryID {
	case "dynamic_secret.registry", "dynamic_secret.postgresql":
		database := dodSecretSubstrateConfig(t, external)
		provider = config.DynamicSecretProviderConfig{
			TenantID: dodSecretIntegrationTenant, ID: target.id, Type: "postgresql",
			AdminDSNRef: fileRef(target.id+"-dsn", []byte(database.AdminDSN)), Database: database.Database,
			AllowedRoles: []string{"reader"}, MaxTTL: "15m", UsernamePrefix: "dod_" + target.id,
		}
	case "dynamic_secret.mysql":
		database := dodSecretSubstrateConfig(t, external)
		provider = config.DynamicSecretProviderConfig{
			TenantID: dodSecretIntegrationTenant, ID: target.id, Type: "mysql",
			AdminDSNRef: fileRef("mysql-dsn", []byte(database.AdminDSN)), Database: database.Database,
			Addr: database.Addr, AccountHost: "%", AllowedRoles: []string{"reader"}, MaxTTL: "15m", UsernamePrefix: "dod_mysql",
		}
	case "dynamic_secret.mongodb":
		database := dodSecretSubstrateConfig(t, external)
		provider = config.DynamicSecretProviderConfig{
			TenantID: dodSecretIntegrationTenant, ID: target.id, Type: "mongodb",
			AdminDSNRef: fileRef("mongo-dsn", []byte(database.AdminDSN)), Database: database.Database,
			AllowedRoles: []string{"reader"}, MaxTTL: "15m", UsernamePrefix: "dod_mongo",
		}
	case "dynamic_secret.aws_iam":
		provider = config.DynamicSecretProviderConfig{
			TenantID: dodSecretIntegrationTenant, ID: target.id, Type: "aws-iam",
			Endpoint: dodParentSubstrateLoopbackBridge(t, external.Endpoint()), Region: "us-east-1", AccessKeyID: "AKIADODADMIN",
			SecretAccessRef: fileRef("aws-admin-secret", []byte("dod-aws-admin-secret")), AllowedRoles: []string{"reader"},
			RoleBindings: map[string]string{"reader": "arn:aws:iam::123456789012:policy/DODReadOnly"}, MaxTTL: "15m",
			AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs, UsernamePrefix: "dod_aws",
		}
	case "dynamic_secret.gcp_iam":
		provider = config.DynamicSecretProviderConfig{
			TenantID: dodSecretIntegrationTenant, ID: target.id, Type: "gcp-iam",
			Endpoint: dodParentSubstrateLoopbackBridge(t, external.Endpoint()), Project: "p", ServiceAccount: "dyn@p.iam.gserviceaccount.com",
			BearerTokenRef: fileRef("gcp-admin-token", []byte("dod-gcp-admin-token")), AllowedRoles: []string{"reader"}, MaxTTL: "15m",
			AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs, UsernamePrefix: "dod-gcp",
		}
	case "dynamic_secret.azure_entra":
		provider = config.DynamicSecretProviderConfig{
			TenantID: dodSecretIntegrationTenant, ID: target.id, Type: "azure-entra",
			Endpoint: dodParentSubstrateLoopbackBridge(t, external.Endpoint()), ApplicationObject: "app-obj", ApplicationClient: "dod-client", AzureTenant: "dod-tenant",
			BearerTokenRef: fileRef("azure-admin-token", []byte("dod-azure-admin-token")), AllowedRoles: []string{"reader"}, MaxTTL: "15m",
			AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs, UsernamePrefix: "dod-azure",
		}
	case "dynamic_secret.kubernetes":
		provider = config.DynamicSecretProviderConfig{
			TenantID: dodSecretIntegrationTenant, ID: target.id, Type: "kubernetes",
			Endpoint: dodParentSubstrateLoopbackBridge(t, external.Endpoint()), Namespace: "apps",
			BearerTokenRef: fileRef("kubernetes-admin-token", []byte("dod-k8s-admin-token")), AllowedRoles: []string{"reader"},
			RoleBindings: map[string]string{"reader": "Role/dod-reader"}, MaxTTL: "15m",
			AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs, UsernamePrefix: "dod-k8s",
		}
	case "dynamic_secret.redis":
		database := dodSecretSubstrateConfig(t, external)
		provider = config.DynamicSecretProviderConfig{
			TenantID: dodSecretIntegrationTenant, ID: target.id, Type: "redis", Addr: database.Addr,
			PasswordRef: fileRef("redis-admin-password", []byte(database.Password)), AllowedRoles: []string{"reader"},
			MaxTTL: "15m", UsernamePrefix: "dod_redis",
		}
	default:
		t.Fatalf("focused dynamic-secret proof has no configuration for %q", entryID)
	}
	cfg.SecretIntegrations.DynamicProviders = []config.DynamicSecretProviderConfig{provider}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("secret integration production config: %v", err)
	}

	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatal(err)
	}
	dodRegisterSecretIntegrationTenant(t, ctx, log, st)
	runSecrets, err := loadRunSecrets(cfg)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	t.Cleanup(runSecrets.Close)
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	signer := dodStartAuthorizedSoftwareSignerProcess(t, t.TempDir())
	deps, err := buildRunDeps(ctx, cfg, st, log, signer, runSecrets, slog.New(slog.NewTextHandler(io.Discard, nil)), guard)
	if err != nil {
		_ = log.Close()
		t.Fatalf("production buildRunDeps: %v", err)
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		_ = log.Close()
		t.Fatalf("Build production deps: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	dynamicDeliveryErrorClass := dodCaptureDynamicDeliveryErrorClass(t, srv)
	dodStartSecretIntegrationDispatcher(t, srv)
	token := dodSecretIntegrationToken(t, st)
	dodProveDynamicSecret(t, entryID, external, srv, st, token, dynamicDeliveryErrorClass, target)
}

// dodCrashFirstVersioningSyncAfterReceiverCommit forces the exact ambiguous
// outbox window for the three version-creating cloud targets. Their retry must
// reuse/reconcile the stable operation instead of creating a second version.
func dodCrashFirstVersioningSyncAfterReceiverCommit(t *testing.T, srv *Server) {
	t.Helper()
	dispatch, ok := srv.obHandler.(*issuanceDispatcher)
	if !ok || dispatch.secretIntegrations == nil {
		t.Fatal("served dispatcher has no secret-integration worker")
	}
	remaining := map[string]bool{
		"aws-secrets-manager":      true,
		"gcp-secret-manager":       true,
		"azure-key-vault":          true,
		"terraform-cloud-opentofu": true,
		"vault-kv-v2":              true,
	}
	var mu sync.Mutex
	dispatch.secretIntegrations.afterSecretSyncDelivery = func(_ context.Context, payload secretSyncOutboxPayload) error {
		mu.Lock()
		defer mu.Unlock()
		if !remaining[payload.Target] {
			return nil
		}
		delete(remaining, payload.Target)
		return errors.New("dod forced crash after receiver commit before local acknowledgement")
	}
}

func dodRunAllSecretSyncProductionAssembly(t *testing.T) {
	syncRegistry := proof.StartCommand(t, "secret_sync.registry")
	syncAWS := proof.StartCommand(t, "secret_sync.aws_secrets_manager")
	syncGCP := proof.StartCommand(t, "secret_sync.gcp_secret_manager")
	syncAzure := proof.StartCommand(t, "secret_sync.azure_key_vault")
	syncGitHub := proof.StartCommand(t, "secret_sync.github_actions")
	syncGitLab := proof.StartCommand(t, "secret_sync.gitlab_ci")
	syncVercel := proof.StartCommand(t, "secret_sync.vercel")
	syncGeneric := proof.StartCommand(t, "secret_sync.generic_ci_json")
	syncKubernetes := proof.StartCommand(t, "secret_sync.kubernetes_secrets")
	syncTerraform := proof.StartCommand(t, "secrets_residuals.terraform_opentofu_native_sync")
	syncVault := proof.StartCommand(t, "secrets_residuals.vault_kv_outbound_sync")

	syncRegistryEndpoint := dodParentSubstrateLoopbackBridge(t, syncRegistry.Endpoint())
	syncAWSEndpoint := dodParentSubstrateLoopbackBridge(t, syncAWS.Endpoint())
	syncGCPEndpoint := dodParentSubstrateLoopbackBridge(t, syncGCP.Endpoint())
	syncAzureEndpoint := dodParentSubstrateLoopbackBridge(t, syncAzure.Endpoint())
	syncGitHubEndpoint := dodParentSubstrateLoopbackBridge(t, syncGitHub.Endpoint())
	syncGitLabEndpoint := dodParentSubstrateLoopbackBridge(t, syncGitLab.Endpoint())
	syncVercelEndpoint := dodParentSubstrateLoopbackBridge(t, syncVercel.Endpoint())
	syncGenericEndpoint := dodParentSubstrateLoopbackBridge(t, syncGeneric.Endpoint())
	syncKubernetesEndpoint := dodParentSubstrateLoopbackBridge(t, syncKubernetes.Endpoint())
	syncTerraformEndpoint := dodParentSubstrateLoopbackBridge(t, syncTerraform.Endpoint())
	syncVaultEndpoint := dodParentSubstrateLoopbackBridge(t, syncVault.Endpoint())

	secretDir := t.TempDir()
	fileRef := func(name string, value []byte) string { return dodSecretIntegrationFile(t, secretDir, name, value) }
	network := func() (bool, []string) { return true, []string{"127.0.0.0/8"} }
	private, cidrs := network()

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Secrets.EnableAPI = true
	cfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "secrets-kek.bin")
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	cfg.CA.CertFile = filepath.Join(t.TempDir(), "issuing-ca.pem")
	cfg.SecretIntegrations.SyncTargets = []config.SecretSyncTargetConfig{
		{TenantID: dodSecretIntegrationTenant, ID: "registry", Type: "generic-ci-json", Endpoint: syncRegistryEndpoint, Provider: "registry", TokenRef: fileRef("registry-sync-token", []byte("dod-registry-token")), AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs},
		{TenantID: dodSecretIntegrationTenant, ID: "aws-secrets-manager", Type: "aws-secrets-manager", Endpoint: syncAWSEndpoint, Region: "us-east-1", AccessKeyID: "AKIADODSYNC", SecretAccessRef: fileRef("aws-sync-secret", []byte("dod-aws-sync-secret")), AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs},
		{TenantID: dodSecretIntegrationTenant, ID: "gcp-secret-manager", Type: "gcp-secret-manager", Endpoint: syncGCPEndpoint, Project: "dod-project", TokenRef: fileRef("gcp-sync-token", []byte("dod-gcp-sync-token")), AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs},
		{TenantID: dodSecretIntegrationTenant, ID: "azure-key-vault", Type: "azure-key-vault", Endpoint: syncAzureEndpoint, APIVersion: "7.4", TokenRef: fileRef("azure-sync-token", []byte("dod-azure-sync-token")), AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs},
		{TenantID: dodSecretIntegrationTenant, ID: "github-actions", Type: "github-actions", Endpoint: syncGitHubEndpoint, Owner: "dod", Repo: "repo", TokenRef: fileRef("github-token", []byte("dod-github-token")), AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs},
		{TenantID: dodSecretIntegrationTenant, ID: "gitlab-ci", Type: "gitlab-ci", Endpoint: syncGitLabEndpoint, ProjectID: "123", TokenRef: fileRef("gitlab-token", []byte("dod-gitlab-token")), AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs},
		{TenantID: dodSecretIntegrationTenant, ID: "vercel", Type: "vercel", Endpoint: syncVercelEndpoint, ProjectID: "dod-project", TokenRef: fileRef("vercel-token", []byte("dod-vercel-token")), Targets: []string{"production"}, AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs},
		{TenantID: dodSecretIntegrationTenant, ID: "generic-ci-json", Type: "generic-ci-json", Endpoint: syncGenericEndpoint, Provider: "generic", TokenRef: fileRef("generic-token", []byte("dod-generic-token")), AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs},
		{TenantID: dodSecretIntegrationTenant, ID: "kubernetes-secrets", Type: "kubernetes-secrets", Endpoint: syncKubernetesEndpoint, Namespace: "apps", TokenRef: fileRef("kubernetes-sync-token", []byte("dod-k8s-sync-token")), AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs},
		{TenantID: dodSecretIntegrationTenant, ID: "terraform-cloud-opentofu", Type: "terraform-cloud-opentofu", Endpoint: syncTerraformEndpoint, WorkspaceID: "ws-dod-opentofu", VariableCategory: "env", Description: "DOD managed variable", TokenRef: fileRef("terraform-sync-token", []byte("dod-terraform-token")), AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs},
		{TenantID: dodSecretIntegrationTenant, ID: "vault-kv-v2", Type: "vault-kv-v2", Endpoint: syncVaultEndpoint, Mount: "team-secrets", PathPrefix: "apps", Field: "value", VaultNamespace: "platform/team-a", TokenRef: fileRef("vault-sync-token", []byte("dod-vault-token")), AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("secret integration production config: %v", err)
	}

	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatal(err)
	}
	dodRegisterSecretIntegrationTenant(t, ctx, log, st)
	runSecrets, err := loadRunSecrets(cfg)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	t.Cleanup(runSecrets.Close)
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	signer := dodStartAuthorizedSoftwareSignerProcess(t, t.TempDir())
	deps, err := buildRunDeps(ctx, cfg, st, log, signer, runSecrets, slog.New(slog.NewTextHandler(io.Discard, nil)), guard)
	if err != nil {
		_ = log.Close()
		t.Fatalf("production buildRunDeps: %v", err)
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		_ = log.Close()
		t.Fatalf("Build production deps: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	dodCrashFirstVersioningSyncAfterReceiverCommit(t, srv)
	dodStartSecretSyncRuntimeWorkers(t, srv)
	token := dodSecretIntegrationToken(t, st)

	sourceValue := []byte("dod-secret-sync-value-2026")
	defer secret.Wipe(sourceValue)
	dodCreateSyncSource(t, srv, token, "dod/sync/source", sourceValue)
	dodProveSecretSync(t, "secret_sync.registry", syncRegistry, srv, token, dodSecretIntegrationTarget{"secret_sync.registry", "registry", "generic"}, sourceValue)
	dodProveSecretSync(t, "secret_sync.aws_secrets_manager", syncAWS, srv, token, dodSecretIntegrationTarget{"secret_sync.aws_secrets_manager", "aws-secrets-manager", "aws"}, sourceValue)
	dodProveSecretSync(t, "secret_sync.gcp_secret_manager", syncGCP, srv, token, dodSecretIntegrationTarget{"secret_sync.gcp_secret_manager", "gcp-secret-manager", "gcp"}, sourceValue)
	dodProveSecretSync(t, "secret_sync.azure_key_vault", syncAzure, srv, token, dodSecretIntegrationTarget{"secret_sync.azure_key_vault", "azure-key-vault", "azure"}, sourceValue)
	dodProveSecretSync(t, "secret_sync.github_actions", syncGitHub, srv, token, dodSecretIntegrationTarget{"secret_sync.github_actions", "github-actions", "github"}, sourceValue)
	dodProveSecretSync(t, "secret_sync.gitlab_ci", syncGitLab, srv, token, dodSecretIntegrationTarget{"secret_sync.gitlab_ci", "gitlab-ci", "gitlab"}, sourceValue)
	dodProveSecretSync(t, "secret_sync.vercel", syncVercel, srv, token, dodSecretIntegrationTarget{"secret_sync.vercel", "vercel", "vercel"}, sourceValue)
	dodProveSecretSync(t, "secret_sync.generic_ci_json", syncGeneric, srv, token, dodSecretIntegrationTarget{"secret_sync.generic_ci_json", "generic-ci-json", "generic"}, sourceValue)
	dodProveSecretSync(t, "secret_sync.kubernetes_secrets", syncKubernetes, srv, token, dodSecretIntegrationTarget{"secret_sync.kubernetes_secrets", "kubernetes-secrets", "kubernetes"}, sourceValue)
	dodProveSecretSync(t, "secrets_residuals.terraform_opentofu_native_sync", syncTerraform, srv, token, dodSecretIntegrationTarget{"secrets_residuals.terraform_opentofu_native_sync", "terraform-cloud-opentofu", "terraform"}, sourceValue)
	dodProveSecretSync(t, "secrets_residuals.vault_kv_outbound_sync", syncVault, srv, token, dodSecretIntegrationTarget{"secrets_residuals.vault_kv_outbound_sync", "vault-kv-v2", "vault"}, sourceValue)
}

func dodRunFocusedSecretSync(t *testing.T, entryID string, external *proof.ExternalSubstrate, target dodSecretIntegrationTarget) {
	t.Helper()
	secretDir := t.TempDir()
	fileRef := func(name string, value []byte) string { return dodSecretIntegrationFile(t, secretDir, name, value) }
	private, cidrs := true, []string{"127.0.0.0/8"}
	endpoint := dodParentSubstrateLoopbackBridge(t, external.Endpoint())

	cfg := config.Default()
	cfg.RateLimit.Enabled = false
	cfg.Secrets.EnableAPI = true
	cfg.Secrets.KEKFile = filepath.Join(t.TempDir(), "secrets-kek.bin")
	cfg.Audit.SigningKeyFile = filepath.Join(t.TempDir(), "audit-signing-key.pem")
	cfg.CA.CertFile = filepath.Join(t.TempDir(), "issuing-ca.pem")
	base := config.SecretSyncTargetConfig{
		TenantID: dodSecretIntegrationTenant, ID: target.id, Endpoint: endpoint,
		AllowPrivate: private, AllowInsecureLoopback: true, PrivateEgressCIDRs: cidrs,
	}
	switch entryID {
	case "secret_sync.registry":
		base.Type, base.Provider = "generic-ci-json", "registry"
		base.TokenRef = fileRef("registry-sync-token", []byte("dod-registry-token"))
	case "secret_sync.aws_secrets_manager":
		base.Type, base.Region, base.AccessKeyID = "aws-secrets-manager", "us-east-1", "AKIADODSYNC"
		base.SecretAccessRef = fileRef("aws-sync-secret", []byte("dod-aws-sync-secret"))
	case "secret_sync.gcp_secret_manager":
		base.Type, base.Project = "gcp-secret-manager", "dod-project"
		base.TokenRef = fileRef("gcp-sync-token", []byte("dod-gcp-sync-token"))
	case "secret_sync.azure_key_vault":
		base.Type, base.APIVersion = "azure-key-vault", "7.4"
		base.TokenRef = fileRef("azure-sync-token", []byte("dod-azure-sync-token"))
	case "secret_sync.github_actions":
		base.Type, base.Owner, base.Repo = "github-actions", "dod", "repo"
		base.TokenRef = fileRef("github-token", []byte("dod-github-token"))
	case "secret_sync.gitlab_ci":
		base.Type, base.ProjectID = "gitlab-ci", "123"
		base.TokenRef = fileRef("gitlab-token", []byte("dod-gitlab-token"))
	case "secret_sync.vercel":
		base.Type, base.ProjectID, base.Targets = "vercel", "dod-project", []string{"production"}
		base.TokenRef = fileRef("vercel-token", []byte("dod-vercel-token"))
	case "secret_sync.generic_ci_json":
		base.Type, base.Provider = "generic-ci-json", "generic"
		base.TokenRef = fileRef("generic-token", []byte("dod-generic-token"))
	case "secret_sync.kubernetes_secrets":
		base.Type, base.Namespace = "kubernetes-secrets", "apps"
		base.TokenRef = fileRef("kubernetes-sync-token", []byte("dod-k8s-sync-token"))
	case "secrets_residuals.terraform_opentofu_native_sync":
		base.Type, base.WorkspaceID, base.VariableCategory = "terraform-cloud-opentofu", "ws-dod-opentofu", "env"
		base.Description = "DOD managed variable"
		base.TokenRef = fileRef("terraform-sync-token", []byte("dod-terraform-token"))
	case "secrets_residuals.vault_kv_outbound_sync":
		base.Type, base.Mount, base.PathPrefix, base.Field = "vault-kv-v2", "team-secrets", "apps", "value"
		base.VaultNamespace = "platform/team-a"
		base.TokenRef = fileRef("vault-sync-token", []byte("dod-vault-token"))
	default:
		t.Fatalf("focused secret-sync proof has no configuration for %q", entryID)
	}
	cfg.SecretIntegrations.SyncTargets = []config.SecretSyncTargetConfig{base}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("secret integration production config: %v", err)
	}

	ctx := context.Background()
	st := newServerTestStore(t)
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(t.TempDir(), "nats")})
	if err != nil {
		t.Fatal(err)
	}
	dodRegisterSecretIntegrationTenant(t, ctx, log, st)
	runSecrets, err := loadRunSecrets(cfg)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	t.Cleanup(runSecrets.Close)
	guard, err := egressGuardFromConfig(cfg.AirGap)
	if err != nil {
		_ = log.Close()
		t.Fatal(err)
	}
	signer := dodStartAuthorizedSoftwareSignerProcess(t, t.TempDir())
	deps, err := buildRunDeps(ctx, cfg, st, log, signer, runSecrets, slog.New(slog.NewTextHandler(io.Discard, nil)), guard)
	if err != nil {
		_ = log.Close()
		t.Fatalf("production buildRunDeps: %v", err)
	}
	srv, err := Build(ctx, deps)
	if err != nil {
		_ = log.Close()
		t.Fatalf("Build production deps: %v", err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	dodCrashFirstVersioningSyncAfterReceiverCommit(t, srv)
	dodStartSecretSyncRuntimeWorkers(t, srv)
	token := dodSecretIntegrationToken(t, st)
	sourceValue := []byte("dod-secret-sync-value-2026")
	defer secret.Wipe(sourceValue)
	dodCreateSyncSource(t, srv, token, "dod/sync/source", sourceValue)
	dodProveSecretSync(t, entryID, external, srv, token, target, sourceValue)
}

func dodStartSecretIntegrationDispatcher(t *testing.T, srv *Server) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.RunDispatcher(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// dodStartSecretSyncRuntimeWorkers mirrors the two shipped leader workers that
// jointly authorize a secret-sync receiver call. The projection tail advances
// the durable event-sequence checkpoint; only then may the dispatcher claim the
// event-derived outbox command. Starting the dispatcher alone would correctly
// leave every post-Build sync intent pending forever.
func dodStartSecretSyncRuntimeWorkers(t *testing.T, srv *Server) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	dispatchDone := make(chan struct{})
	tailDone := make(chan struct{})
	go func() {
		defer close(dispatchDone)
		srv.RunDispatcher(ctx)
	}()
	go func() {
		defer close(tailDone)
		srv.RunProjectionTail(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-dispatchDone
		<-tailDone
	})
}

type dodSubstrateConfig struct {
	Kind     string `json:"kind"`
	AdminDSN string `json:"admin_dsn"`
	Addr     string `json:"addr"`
	Database string `json:"database"`
	Password string `json:"password"`
}

func dodStartDatabaseSecretSubstrate(t *testing.T, entryID string) (*proof.ExternalSubstrate, dodSubstrateConfig) {
	t.Helper()
	external := proof.StartCommand(t, entryID)
	return external, dodSecretSubstrateConfig(t, external)
}

func dodSecretSubstrateConfig(t *testing.T, external *proof.ExternalSubstrate) dodSubstrateConfig {
	t.Helper()
	client := &http.Client{Timeout: 150 * time.Second}
	response, err := client.Get(external.Endpoint() + "/dod/config")
	if err != nil {
		t.Fatalf("read secret substrate config: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if readErr != nil {
		t.Fatalf("read secret substrate config body: %v", readErr)
	}
	var cfg dodSubstrateConfig
	decodeErr := json.Unmarshal(body, &cfg)
	if response.StatusCode != http.StatusOK || decodeErr != nil || cfg.Kind == "" {
		t.Fatalf("invalid secret substrate config status=%d decode=%v body=%s", response.StatusCode, decodeErr, body)
	}
	host, err := dodRuntimeDockerHost()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = dodSecretSubstrateConfigForHost(cfg, host)
	if err != nil {
		t.Fatalf("invalid secret substrate database endpoint: %v", err)
	}
	return cfg
}

// dodSecretSubstrateConfigForHost rewrites only the four parent-owned database
// receivers. Native execution uses loopback unchanged. In the reviewed Linux
// runner, the same published Docker ports are reached through Docker Desktop's
// fixed host name. The receiver may never choose a different source or target
// host, so a forged config cannot turn this proof into an arbitrary network dial.
func dodSecretSubstrateConfigForHost(cfg dodSubstrateConfig, host string) (dodSubstrateConfig, error) {
	if host != "127.0.0.1" && host != "host.docker.internal" {
		return dodSubstrateConfig{}, errors.New("runtime Docker host is outside the closed proof allowlist")
	}
	var err error
	switch cfg.Kind {
	case "postgresql":
		cfg.AdminDSN, err = dodRewriteSecretDatabaseURL(cfg.AdminDSN, host, "postgres")
	case "mysql":
		originalAddr := cfg.Addr
		cfg.Addr, err = dodRewriteSecretDatabaseHostPort(originalAddr, host)
		if err == nil {
			needle := "@tcp(" + originalAddr + ")/"
			if strings.Count(cfg.AdminDSN, needle) != 1 {
				err = errors.New("MySQL substrate DSN does not bind its exact loopback address")
			} else {
				cfg.AdminDSN = strings.Replace(cfg.AdminDSN, needle, "@tcp("+cfg.Addr+")/", 1)
			}
		}
	case "mongodb":
		cfg.AdminDSN, err = dodRewriteSecretDatabaseURL(cfg.AdminDSN, host, "mongodb")
	case "redis":
		cfg.Addr, err = dodRewriteSecretDatabaseHostPort(cfg.Addr, host)
	case "http":
		return cfg, nil
	default:
		return dodSubstrateConfig{}, fmt.Errorf("unsupported secret substrate kind %q", cfg.Kind)
	}
	if err != nil {
		return dodSubstrateConfig{}, err
	}
	return cfg, nil
}

func dodRewriteSecretDatabaseURL(raw, host, scheme string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != scheme || parsed.Hostname() != "127.0.0.1" || parsed.Port() == "" || parsed.Opaque != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%s substrate DSN is not the exact loopback URL shape", scheme)
	}
	if _, err := dodSecretDatabasePort(parsed.Port()); err != nil {
		return "", err
	}
	parsed.Host = net.JoinHostPort(host, parsed.Port())
	return parsed.String(), nil
}

func dodRewriteSecretDatabaseHostPort(raw, host string) (string, error) {
	sourceHost, port, err := net.SplitHostPort(raw)
	if err != nil || sourceHost != "127.0.0.1" {
		return "", errors.New("secret substrate address is not an exact loopback host:port")
	}
	if _, err := dodSecretDatabasePort(port); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, port), nil
}

func dodSecretDatabasePort(raw string) (int, error) {
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("secret substrate database port is outside 1..65535")
	}
	return port, nil
}

func TestDODSecretSubstrateConfigRewritesCrossHostDatabaseEndpoints(t *testing.T) {
	const host = "host.docker.internal"
	tests := []struct {
		name     string
		cfg      dodSubstrateConfig
		wantDSN  string
		wantAddr string
	}{
		{"postgresql", dodSubstrateConfig{Kind: "postgresql", AdminDSN: "postgres://postgres:dod-admin@127.0.0.1:5432/app?sslmode=disable"}, "@host.docker.internal:5432/", ""},
		{"mysql", dodSubstrateConfig{Kind: "mysql", AdminDSN: "root:dod-admin@tcp(127.0.0.1:3306)/app?parseTime=true", Addr: "127.0.0.1:3306"}, "@tcp(host.docker.internal:3306)/", "host.docker.internal:3306"},
		{"mongodb", dodSubstrateConfig{Kind: "mongodb", AdminDSN: "mongodb://root:dod-admin@127.0.0.1:27017/app?authSource=admin"}, "@host.docker.internal:27017/", ""},
		{"redis", dodSubstrateConfig{Kind: "redis", Addr: "127.0.0.1:6379"}, "", "host.docker.internal:6379"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := dodSecretSubstrateConfigForHost(test.cfg, host)
			if err != nil {
				t.Fatal(err)
			}
			if test.wantDSN != "" && !strings.Contains(got.AdminDSN, test.wantDSN) {
				t.Errorf("rewritten DSN does not use cross-host endpoint: %q", got.AdminDSN)
			}
			if got.Addr != test.wantAddr {
				t.Errorf("rewritten address = %q, want %q", got.Addr, test.wantAddr)
			}
			if strings.Contains(got.AdminDSN, "@127.0.0.1:") || strings.HasPrefix(got.Addr, "127.0.0.1:") {
				t.Errorf("rewritten config retained child-container loopback: %+v", got)
			}
		})
	}
}

func TestDODSecretSubstrateConfigRejectsUntrustedDatabaseHosts(t *testing.T) {
	tests := []dodSubstrateConfig{
		{Kind: "postgresql", AdminDSN: "postgres://postgres:dod-admin@attacker.test:5432/app"},
		{Kind: "mysql", AdminDSN: "root:dod-admin@tcp(attacker.test:3306)/app", Addr: "attacker.test:3306"},
		{Kind: "mongodb", AdminDSN: "mongodb://root:dod-admin@attacker.test:27017/app"},
		{Kind: "redis", Addr: "attacker.test:6379"},
	}
	for _, cfg := range tests {
		if _, err := dodSecretSubstrateConfigForHost(cfg, "host.docker.internal"); err == nil {
			t.Errorf("accepted %s substrate with an untrusted source host", cfg.Kind)
		}
	}
	if _, err := dodSecretSubstrateConfigForHost(dodSubstrateConfig{Kind: "redis", Addr: "127.0.0.1:6379"}, "attacker.test"); err == nil {
		t.Fatal("accepted an untrusted runtime Docker host")
	}
}

func dodSecretIntegrationFile(t *testing.T, dir, name string, value []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	return "file:" + path
}

func dodSecretIntegrationToken(t *testing.T, st *store.Store) string {
	t.Helper()
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateAPIToken(context.Background(), store.APITokenRecord{
		TenantID: dodSecretIntegrationTenant, TokenHash: hash, Subject: "dod-secret-integrations",
		Scopes: []string{string(authz.SecretsRead), string(authz.SecretsWrite)},
	}); err != nil {
		secret.Wipe(raw)
		t.Fatal(err)
	}
	token := secrettext.String(raw)
	secret.Wipe(raw)
	return token
}

func dodRegisterSecretIntegrationTenant(t *testing.T, ctx context.Context, log *events.Log, st *store.Store) {
	t.Helper()
	service := app.New(log, st, nil)
	defer service.Close()
	if err := service.RegisterTenant(ctx, dodSecretIntegrationTenant, "DoD secret integrations",
		"dod-secret-integrations-register-tenant"); err != nil {
		t.Fatalf("register secret-integration tenant through event spine: %v", err)
	}
}

func dodProveDynamicSecret(t *testing.T, entryID string, external *proof.ExternalSubstrate, srv *Server, st *store.Store, token string, deliveryErrorClass func() string, target dodSecretIntegrationTarget) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"provider": target.id, "role": "reader", "ttl_seconds": 300})
	idempotencyKey := "dod-" + strings.ReplaceAll(target.entryID, ".", "-") + "-issue"
	firstSession := dodStartDynamicLeaseProofSession(t, entryID, external, srv, st, token, idempotencyKey, body, deliveryErrorClass)
	firstBody := firstSession.ResponseBody()
	if firstSession.StatusCode() != http.StatusCreated {
		t.Fatalf("%s issue status=%d body=%s", target.entryID, firstSession.StatusCode(), firstBody)
	}
	var first dodDynamicLeaseWire
	if err := json.Unmarshal(firstBody, &first); err != nil || first.ID == "" || len(first.Credential) == 0 || first.State != "active" {
		t.Fatalf("%s invalid lease response: %v body=%s", target.entryID, err, firstBody)
	}
	firstRecord, err := st.GetDynamicSecretLease(context.Background(), dodSecretIntegrationTenant, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	dodUseDynamicCredential(t, external, target, firstRecord.BackendRef, first.Credential)
	dodRenewDynamicLease(t, srv, token, first.ID, "dod-renew-"+first.ID)
	rotateStatus, rotateBody := dodWaitDynamicLeaseResponse(t, target.entryID, external, srv, st, token, "dod-"+strings.ReplaceAll(target.entryID, ".", "-")+"-rotate", body, deliveryErrorClass)
	if rotateStatus != http.StatusCreated {
		t.Fatalf("%s rotate issue status=%d body=%s", target.entryID, rotateStatus, rotateBody)
	}
	var rotated dodDynamicLeaseWire
	if err := json.Unmarshal(rotateBody, &rotated); err != nil || rotated.ID == "" || len(rotated.Credential) == 0 || rotated.State != "active" {
		t.Fatalf("%s invalid rotated lease response: %v body=%s", target.entryID, err, rotateBody)
	}
	if bytes.Equal(first.Credential, rotated.Credential) {
		t.Fatalf("%s rotation returned the original credential", target.entryID)
	}
	rotatedRecord, err := st.GetDynamicSecretLease(context.Background(), dodSecretIntegrationTenant, rotated.ID)
	if err != nil {
		t.Fatal(err)
	}
	dodUseDynamicCredential(t, external, target, rotatedRecord.BackendRef, rotated.Credential)
	dodRevokeDynamicLease(t, srv, token, first.ID, "dod-revoke-"+first.ID)
	dodRevokeDynamicLease(t, srv, token, rotated.ID, "dod-revoke-"+rotated.ID)
	dodWaitDynamicLeaseState(t, st, first.ID, store.DynamicSecretLeaseRevoked)
	dodWaitDynamicLeaseState(t, st, rotated.ID, store.DynamicSecretLeaseRevoked)
	revocationReceipt := dodAssertDynamicCredentialRevoked(t, external, target, firstRecord.BackendRef, first.Credential)
	dodAssertDynamicCredentialRevoked(t, external, target, rotatedRecord.BackendRef, rotated.Credential)
	executionReceipt := external.StopAndReceipt()
	firstSession.Complete(proof.CredentialLifecycle(proof.CredentialLifecycleProbe{
		Issued: first.Credential, Rotated: rotated.Credential, RevocationReceipt: revocationReceipt,
		Exported: firstSession.ResponseBody(), ExecutionReceipt: executionReceipt,
	}))
	secret.Wipe(first.Credential)
	secret.Wipe(rotated.Credential)
}

func dodStartDynamicLeaseProofSession(t *testing.T, entryID string, external *proof.ExternalSubstrate, srv *Server, st *store.Store, token, idempotencyKey string, body []byte, deliveryErrorClass func() string) *proof.Session {
	t.Helper()
	status, responseBody := dodWaitDynamicLeaseResponse(t, entryID, external, srv, st, token, idempotencyKey, body, deliveryErrorClass)
	if status != http.StatusCreated {
		t.Fatalf("%s issue status=%d body=%s", entryID, status, responseBody)
	}
	// Bind the final successful idempotent replay to the gate-owned route,
	// nonce, shipped profile, and external substrate receipt. The earlier calls
	// exercise the documented 504/retry contract; only a real 201 may create the
	// proof session.
	served := dodSecretAPIRequest(t, http.MethodPost, "/api/v1/secrets/leases", token, idempotencyKey, body)
	return proof.Start(t, entryID, srv.Handler(), served)
}

func dodWaitDynamicLeaseResponse(t *testing.T, entryID string, external *proof.ExternalSubstrate, srv *Server, st *store.Store, token, idempotencyKey string, body []byte, deliveryErrorClass func() string) (int, []byte) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		request := dodSecretAPIRequest(t, http.MethodPost, "/api/v1/secrets/leases", token, idempotencyKey, body)
		status, responseBody := dodServeSecretRequest(t, srv, request)
		switch status {
		case http.StatusCreated:
			return status, responseBody
		case http.StatusGatewayTimeout:
			if time.Now().After(deadline) {
				lease, leaseErr := st.GetDynamicSecretLeaseByIdempotencyKey(context.Background(), dodSecretIntegrationTenant, idempotencyKey)
				outboxStatus, outboxAttempts, outboxErrorClass := "unavailable", -1, "unavailable"
				if leaseErr == nil {
					if outbox, outboxErr := srv.outbox.Get(context.Background(), dodSecretIntegrationTenant, lease.IssueOutboxID); outboxErr == nil {
						outboxStatus, outboxAttempts = outbox.Status, outbox.Attempts
						outboxErrorClass = dodSecretIntegrationErrorClass(outbox.LastError)
					}
				}
				t.Fatalf("%s remained pending after idempotent retries: body=%s lease_state=%s lease_err=%v prepared=%t outbox_status=%s outbox_attempts=%d outbox_error_class=%s live_error_class=%s bridge=%s",
					entryID, responseBody, lease.State, leaseErr, len(lease.SealedPreparation) > 0, outboxStatus, outboxAttempts, outboxErrorClass, deliveryErrorClass(), dodSecretBridgeStatus(external))
			}
			time.Sleep(100 * time.Millisecond)
		default:
			return status, responseBody
		}
	}
}

func dodSecretBridgeStatus(external *proof.ExternalSubstrate) string {
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(external.Endpoint() + "/dod/bridge-status")
	if err != nil {
		return "unreachable"
	}
	defer func() { _ = response.Body.Close() }()
	var status struct {
		Accepts          int    `json:"accepts"`
		UpstreamConnects int    `json:"upstream_connects"`
		LastErrno        int    `json:"last_errno"`
		UpstreamRoute    string `json:"upstream_route"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&status) != nil {
		return "invalid"
	}
	return fmt.Sprintf("accepts:%d,upstream:%d,errno:%d,route:%s", status.Accepts, status.UpstreamConnects, status.LastErrno, status.UpstreamRoute)
}

func dodSecretIntegrationErrorClass(raw string) string {
	value := strings.ToLower(raw)
	for _, candidate := range []struct {
		contains string
		class    string
	}{
		{"dynsecret postgres: connect failed", "database-connect"},
		{"dynsecret postgres: lookup role", "postgres-role-lookup"},
		{"dynsecret postgres: create role failed", "postgres-role-create"},
		{"dynsecret postgres: clean interrupted role", "postgres-reconcile"},
		{"failed to connect", "database-connect"},
		{"connection refused", "connection-refused"},
		{"no such host", "dns-failure"},
		{"i/o timeout", "network-timeout"},
		{"context deadline exceeded", "deadline"},
		{"password authentication failed", "authentication"},
		{"permission denied", "authorization"},
		{"no route to host", "network-route"},
	} {
		if strings.Contains(value, candidate.contains) {
			return candidate.class
		}
	}
	if raw == "" {
		return "none"
	}
	// Do not print upstream error text: vendor responses may echo credentials.
	return "other-" + crypto.SHA256Hex([]byte(raw))[:12]
}

func dodCaptureDynamicDeliveryErrorClass(t *testing.T, srv *Server) func() string {
	t.Helper()
	dispatch, ok := srv.obHandler.(*issuanceDispatcher)
	if !ok || dispatch.secretIntegrations == nil {
		t.Fatal("served dispatcher has no secret-integration worker")
	}
	var mu sync.Mutex
	last := "none"
	dispatch.secretIntegrations.afterDynamicSecretDelivery = func(err error) {
		if err == nil {
			return
		}
		classified := dodSecretIntegrationErrorClass(err.Error())
		mu.Lock()
		last = classified
		mu.Unlock()
	}
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return last
	}
}

func dodWaitDynamicLeaseState(t *testing.T, st *store.Store, leaseID string, want store.DynamicSecretLeaseState) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		record, err := st.GetDynamicSecretLease(context.Background(), dodSecretIntegrationTenant, leaseID)
		if err == nil && record.State == want {
			// A revocation-requested event stops serving the lease immediately, but
			// provider deletion is a later outbox effect. The DoD receipt must wait
			// for that external effect, not merely the local revoked state.
			if want != store.DynamicSecretLeaseRevoked || record.RevocationStatus == store.DynamicSecretRevocationCompleted {
				return
			}
			if record.RevocationStatus == store.DynamicSecretRevocationFailed {
				t.Fatalf("dynamic lease %s provider revocation failed: %s", leaseID, record.LastError)
			}
		}
		if err == nil && record.State == store.DynamicSecretLeaseFailed {
			t.Fatalf("dynamic lease %s failed while waiting for %s: %s", leaseID, want, record.LastError)
		}
		if time.Now().After(deadline) {
			t.Fatalf("dynamic lease %s did not reach %s: state=%s err=%v", leaseID, want, record.State, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func dodUseDynamicCredential(t *testing.T, external *proof.ExternalSubstrate, target dodSecretIntegrationTarget, backendRef string, credential []byte) []byte {
	t.Helper()
	ctx := context.Background()
	switch target.kind {
	case "postgresql":
		conn, err := pgx.Connect(ctx, secrettext.String(credential))
		if err != nil {
			t.Fatalf("%s generated PostgreSQL credential login: %v", target.entryID, err)
		}
		defer func() { _ = conn.Close(ctx) }()
		var one int
		if err := conn.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
			t.Fatalf("%s generated PostgreSQL credential query: %v", target.entryID, err)
		}
	case "mysql":
		db, err := dynsecret.OpenMySQLExecutor(ctx, credential)
		if err != nil {
			t.Fatalf("generated MySQL credential login: %v", err)
		}
		defer func() { _ = db.Close() }()
		var one int
		if err := db.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
			t.Fatalf("generated MySQL credential query: %v", err)
		}
	case "mongodb":
		client, err := dynsecret.OpenMongoAdmin(ctx, credential)
		if err != nil {
			t.Fatalf("generated MongoDB credential login: %v", err)
		}
		defer func() { _ = client.Close(context.Background()) }()
	case "redis":
		conn := dodRedisCredentialConnection(t, credential)
		defer func() { _ = conn.Close() }()
	case "aws-iam", "gcp-iam", "azure-entra", "kubernetes":
		return dodCloudDynamicAuth(t, external, target, credential, true)
	default:
		t.Fatalf("unknown dynamic proof kind %q", target.kind)
	}
	return dodDynamicReadback(t, external.Endpoint(), backendRef, "active", http.StatusOK)
}

func dodAssertDynamicCredentialRevoked(t *testing.T, external *proof.ExternalSubstrate, target dodSecretIntegrationTarget, backendRef string, credential []byte) []byte {
	t.Helper()
	switch target.kind {
	case "postgresql", "mysql", "mongodb", "redis":
		return dodDynamicReadback(t, external.Endpoint(), backendRef, "absent", http.StatusOK)
	default:
		return dodCloudDynamicAuth(t, external, target, credential, false)
	}
}

func dodDynamicReadback(t *testing.T, endpoint, principal, phase string, expected int) []byte {
	t.Helper()
	query := url.Values{"principal": []string{principal}, "phase": []string{phase}}
	deadline := time.Now().Add(10 * time.Second)
	for {
		response, err := http.Get(endpoint + "/dod/readback?" + query.Encode())
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
		if response.StatusCode == expected {
			return body
		}
		if time.Now().After(deadline) {
			t.Fatalf("dynamic readback phase=%s status=%d body=%s", phase, response.StatusCode, body)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func dodCloudDynamicAuth(t *testing.T, external *proof.ExternalSubstrate, target dodSecretIntegrationTarget, credential []byte, active bool) []byte {
	t.Helper()
	query := url.Values{}
	req, err := http.NewRequest(http.MethodGet, external.Endpoint()+"/dod/auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	switch target.kind {
	case "aws-iam":
		var value struct {
			AccessKeyID     string         `json:"access_key_id"`
			SecretAccessKey dodSecretBytes `json:"secret_access_key"`
		}
		if err := json.Unmarshal(credential, &value); err != nil {
			t.Fatal(err)
		}
		dodSignAWSWorkloadRequest(req, value.AccessKeyID, value.SecretAccessKey)
		defer secret.Wipe(value.SecretAccessKey)
	case "gcp-iam":
		var value struct {
			PrivateKeyID string         `json:"private_key_id"`
			PrivateKey   dodSecretBytes `json:"private_key"`
		}
		if err := json.Unmarshal(credential, &value); err != nil {
			t.Fatal(err)
		}
		signature, err := crypto.SignUploadableRSAKey(value.PrivateKey, []byte("trstctl-dod-gcp-auth"))
		secret.Wipe(value.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		query.Set("id", value.PrivateKeyID)
		query.Set("signature", base64.StdEncoding.EncodeToString(signature))
	case "azure-entra":
		var value struct {
			ClientSecret dodSecretBytes `json:"client_secret"`
		}
		if err := json.Unmarshal(credential, &value); err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+secrettext.String(value.ClientSecret))
		defer secret.Wipe(value.ClientSecret)
	case "kubernetes":
		req.Header.Set("Authorization", "Bearer "+secrettext.String(credential))
	}
	req.URL.RawQuery = query.Encode()
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	want := http.StatusUnauthorized
	if active {
		want = http.StatusOK
	}
	if response.StatusCode != want {
		t.Fatalf("%s credential active=%t auth status=%d body=%s", target.entryID, active, response.StatusCode, body)
	}
	return body
}

func dodRedisCredentialConnection(t *testing.T, credential []byte) net.Conn {
	t.Helper()
	prefix := []byte("redis://")
	if !bytes.HasPrefix(credential, prefix) {
		t.Fatal("invalid Redis credential URI")
	}
	rest := credential[len(prefix):]
	at := bytes.LastIndexByte(rest, '@')
	if at <= 0 {
		t.Fatal("invalid Redis credential authority")
	}
	colon := bytes.IndexByte(rest[:at], ':')
	if colon <= 0 {
		t.Fatal("invalid Redis credential authority")
	}
	user, password := rest[:colon], rest[colon+1:at]
	hostEnd := bytes.IndexByte(rest[at+1:], '/')
	if hostEnd < 0 {
		t.Fatal("invalid Redis credential host")
	}
	addr := string(rest[at+1 : at+1+hostEnd])
	dbBytes := rest[at+1+hostEnd+1:]
	if len(dbBytes) == 0 || bytes.IndexAny(dbBytes, "?#") >= 0 {
		t.Fatal("invalid Redis credential database")
	}
	db, err := strconv.Atoi(string(dbBytes))
	if err != nil || db < 0 {
		t.Fatal("invalid Redis credential database")
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	redisRoundTrip := func(parts ...[]byte) string {
		var body bytes.Buffer
		fmt.Fprintf(&body, "*%d\r\n", len(parts))
		for _, part := range parts {
			fmt.Fprintf(&body, "$%d\r\n", len(part))
			body.Write(part)
			body.WriteString("\r\n")
		}
		if _, err := conn.Write(body.Bytes()); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Redis credential command response err=%v", err)
		}
		return line
	}
	requireRedisPrefix := func(want string, parts ...[]byte) {
		t.Helper()
		if line := redisRoundTrip(parts...); !strings.HasPrefix(line, want) {
			t.Fatalf("Redis credential command response=%q, want prefix %q", line, want)
		}
	}
	requireRedisPrefix("+", []byte("AUTH"), user, password)
	requireRedisPrefix("+", []byte("PING"))
	requireRedisPrefix("+", []byte("SELECT"), []byte(strconv.Itoa(db)))
	requireRedisPrefix("$-1\r\n", []byte("GET"), []byte("trstctl:dod:read-only-probe"))
	requireRedisPrefix("-NOPERM", []byte("SET"), []byte("trstctl:dod:write-denied"), []byte("must-not-land"))
	// A denied write must not poison or close the authenticated connection that
	// the external active-use/readback and later revocation checks observe.
	requireRedisPrefix("+", []byte("PING"))
	return conn
}

func dodRenewDynamicLease(t *testing.T, srv *Server, token, leaseID, idempotency string) {
	t.Helper()
	req := dodSecretAPIRequest(t, http.MethodPost, "/api/v1/secrets/leases/"+leaseID+"/renew", token, idempotency, []byte(`{"extend_seconds":30}`))
	status, body := dodServeSecretRequest(t, srv, req)
	if status != http.StatusOK {
		t.Fatalf("renew lease %s status=%d body=%s", leaseID, status, body)
	}
}

func dodRevokeDynamicLease(t *testing.T, srv *Server, token, leaseID, idempotency string) {
	t.Helper()
	req := dodSecretAPIRequest(t, http.MethodPost, "/api/v1/secrets/leases/"+leaseID+"/revoke", token, idempotency, []byte(`{}`))
	status, body := dodServeSecretRequest(t, srv, req)
	if status != http.StatusOK {
		t.Fatalf("revoke lease %s status=%d body=%s", leaseID, status, body)
	}
}

func dodCreateSyncSource(t *testing.T, srv *Server, token, name string, value []byte) {
	t.Helper()
	body := make([]byte, 0, len(name)+len(value)+32)
	body = append(body, `{"name":`...)
	body = appendDODJSONString(body, []byte(name))
	body = append(body, `,"value":`...)
	body = appendDODJSONString(body, value)
	body = append(body, '}')
	req := dodSecretAPIRequest(t, http.MethodPost, "/api/v1/secrets/store", token, "dod-create-sync-source", body)
	status, response := dodServeSecretRequest(t, srv, req)
	secret.Wipe(body)
	if status != http.StatusCreated {
		t.Fatalf("create sync source status=%d body=%s", status, response)
	}
}

func dodProveSecretSync(t *testing.T, entryID string, external *proof.ExternalSubstrate, srv *Server, token string, target dodSecretIntegrationTarget, sourceValue []byte) {
	t.Helper()
	remoteKey := "DOD_" + strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(target.entryID))
	body, _ := json.Marshal(map[string]string{"name": "dod/sync/source", "target": target.id, "remote_key": remoteKey})
	req := dodSecretAPIRequest(t, http.MethodPost, "/api/v1/secrets/syncs", token, "dod-"+strings.ReplaceAll(target.entryID, ".", "-"), body)
	session := proof.Start(t, entryID, srv.Handler(), req)
	if session.StatusCode() != http.StatusOK || !bytes.Contains(session.ResponseBody(), []byte(`"enqueued":true`)) {
		t.Fatalf("%s sync response status=%d body=%s", target.entryID, session.StatusCode(), session.ResponseBody())
	}
	endpoint := external.Endpoint()
	readback := dodWaitSecretSyncReadback(t, external, srv, target.id, remoteKey)
	if !bytes.Equal(readback, sourceValue) {
		t.Fatalf("%s external readback differs from source", target.entryID)
	}
	if target.kind == "aws" || target.kind == "gcp" || target.kind == "azure" || target.kind == "terraform" || target.kind == "vault" {
		dodAssertSecretSyncReconciledOnce(t, endpoint, remoteKey, target.kind)
	}
	executionReceipt := external.StopAndReceipt()
	session.Complete(proof.ExternalWrite(proof.ExternalWriteProbe{
		Destination: []byte("secret-sync://" + target.entryID + "/" + remoteKey),
		Written:     sourceValue, ReadBack: readback, ExecutionReceipt: executionReceipt,
	}))
}

func dodAssertSecretSyncReconciledOnce(t *testing.T, endpoint, remoteKey, kind string) {
	t.Helper()
	query := url.Values{"key": []string{remoteKey}}
	deadline := time.Now().Add(15 * time.Second)
	var last struct {
		Versions     int    `json:"versions"`
		Reconciled   bool   `json:"reconciled"`
		NativeWire   bool   `json:"native_wire"`
		Sensitive    bool   `json:"sensitive"`
		Category     string `json:"category"`
		CASConflicts int    `json:"cas_conflicts"`
		CASPreserved bool   `json:"cas_preserved"`
	}
	var lastStatus int
	var lastErr error
	for time.Now().Before(deadline) {
		response, err := http.Get(endpoint + "/dod/sync-state?" + query.Encode())
		if err == nil {
			last = struct {
				Versions     int    `json:"versions"`
				Reconciled   bool   `json:"reconciled"`
				NativeWire   bool   `json:"native_wire"`
				Sensitive    bool   `json:"sensitive"`
				Category     string `json:"category"`
				CASConflicts int    `json:"cas_conflicts"`
				CASPreserved bool   `json:"cas_preserved"`
			}{}
			lastStatus = response.StatusCode
			lastErr = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&last)
			_ = response.Body.Close()
			providerEvidence := true
			if kind == "terraform" {
				providerEvidence = last.NativeWire && last.Sensitive && last.Category == "env"
			}
			if kind == "vault" {
				providerEvidence = last.NativeWire && last.CASConflicts == 1 && last.CASPreserved
			}
			if lastStatus == http.StatusOK && lastErr == nil && last.Versions == 1 && last.Reconciled && providerEvidence {
				return
			}
		} else {
			lastErr = err
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("secret sync replay state kind=%s status=%d decode=%v versions=%d reconciled=%t native=%t sensitive=%t category=%q cas_conflicts=%d cas_preserved=%t",
		kind, lastStatus, lastErr, last.Versions, last.Reconciled, last.NativeWire,
		last.Sensitive, last.Category, last.CASConflicts, last.CASPreserved)
}

func dodWaitSecretSyncReadback(t *testing.T, external *proof.ExternalSubstrate, srv *Server, targetID, remoteKey string) []byte {
	t.Helper()
	query := url.Values{"key": []string{remoteKey}}
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	var lastStatus int
	var lastBody []byte
	for {
		response, err := http.Get(external.Endpoint() + "/dod/readback?" + query.Encode())
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			_ = response.Body.Close()
			lastStatus, lastBody, lastErr = response.StatusCode, body, readErr
			if readErr == nil && response.StatusCode == http.StatusOK {
				return body
			}
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			job, jobErr := srv.store.GetLatestSecretSyncJob(context.Background(), dodSecretIntegrationTenant, "dod/sync/source", targetID, remoteKey)
			outboxStatus, outboxAttempts, outboxErrorClass := "unavailable", -1, "unavailable"
			if jobErr == nil {
				if outbox, outboxErr := srv.outbox.Get(context.Background(), dodSecretIntegrationTenant, job.OutboxID); outboxErr == nil {
					outboxStatus, outboxAttempts = outbox.Status, outbox.Attempts
					outboxErrorClass = dodSecretIntegrationErrorClass(outbox.LastError)
				}
			}
			t.Fatalf("secret sync readback key=%s status=%d err=%v response_class=%s job_status=%s job_attempts=%d job_error_class=%s job_err=%v outbox_status=%s outbox_attempts=%d outbox_error_class=%s bridge=%s",
				remoteKey, lastStatus, lastErr, dodSecretIntegrationErrorClass(string(lastBody)), job.Status, job.Attempts,
				dodSecretIntegrationErrorClass(job.LastError), jobErr, outboxStatus, outboxAttempts, outboxErrorClass,
				dodSecretBridgeStatus(external))
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// dodSignAWSWorkloadRequest uses the generated IAM key as an AWS workload
// would: it signs an independent STS-scoped request. The external substrate
// recomputes the entire canonical SigV4 value and rejects this request after
// trstctl revokes the access key.
func dodSignAWSWorkloadRequest(req *http.Request, accessKeyID string, secretAccessKey []byte) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	const signedHeaders = "host;x-amz-date"
	canonicalHeaders := "host:" + req.URL.Host + "\n" + "x-amz-date:" + amzDate + "\n"
	canonicalRequest := strings.Join([]string{
		req.Method, req.URL.EscapedPath(), "", canonicalHeaders,
		signedHeaders, crypto.SHA256Hex(nil),
	}, "\n")
	credentialScope := dateStamp + "/us-east-1/sts/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, credentialScope,
		crypto.SHA256Hex([]byte(canonicalRequest)),
	}, "\n")
	seed := make([]byte, 0, len("AWS4")+len(secretAccessKey))
	seed = append(seed, "AWS4"...)
	seed = append(seed, secretAccessKey...)
	kDate := crypto.HMACSHA256(seed, []byte(dateStamp))
	secret.Wipe(seed)
	kRegion := crypto.HMACSHA256(kDate, []byte("us-east-1"))
	secret.Wipe(kDate)
	kService := crypto.HMACSHA256(kRegion, []byte("sts"))
	secret.Wipe(kRegion)
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	secret.Wipe(kService)
	signature := crypto.HMACSHA256(kSigning, []byte(stringToSign))
	secret.Wipe(kSigning)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKeyID+"/"+credentialScope+
		", SignedHeaders="+signedHeaders+", Signature="+hex.EncodeToString(signature))
	secret.Wipe(signature)
}

func dodSecretAPIRequest(t *testing.T, method, path, token, idempotency string, body []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if idempotency != "" {
		req.Header.Set("Idempotency-Key", idempotency)
	}
	return req
}

func dodServeSecretRequest(t *testing.T, srv *Server, req *http.Request) (int, []byte) {
	t.Helper()
	recorder := &dodSecretHTTPRecorder{header: make(http.Header), status: http.StatusOK}
	srv.Handler().ServeHTTP(recorder, req)
	return recorder.status, recorder.body.Bytes()
}

type dodSecretHTTPRecorder struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *dodSecretHTTPRecorder) Header() http.Header            { return r.header }
func (r *dodSecretHTTPRecorder) WriteHeader(status int)         { r.status = status }
func (r *dodSecretHTTPRecorder) Write(body []byte) (int, error) { return r.body.Write(body) }

type dodSecretBytes []byte

func (b *dodSecretBytes) UnmarshalJSON(raw []byte) error {
	value, err := decodeDODJSONString(raw)
	if err != nil {
		return err
	}
	*b = value
	return nil
}

func decodeDODJSONString(raw []byte) ([]byte, error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, errors.New("expected JSON string")
	}
	out := make([]byte, 0, len(raw)-2)
	for i := 1; i < len(raw)-1; i++ {
		value := raw[i]
		if value != '\\' {
			out = append(out, value)
			continue
		}
		i++
		if i >= len(raw)-1 {
			return nil, errors.New("invalid JSON escape")
		}
		switch raw[i] {
		case '"', '\\', '/':
			out = append(out, raw[i])
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			if i+4 >= len(raw) {
				return nil, errors.New("short JSON unicode escape")
			}
			var runeValue rune
			for _, digit := range raw[i+1 : i+5] {
				nibble, ok := dodHexNibble(digit)
				if !ok {
					return nil, errors.New("invalid JSON unicode escape")
				}
				runeValue = runeValue<<4 | rune(nibble)
			}
			out = utf8.AppendRune(out, runeValue)
			i += 4
		default:
			return nil, errors.New("invalid JSON escape")
		}
	}
	return out, nil
}

func appendDODJSONString(dst, src []byte) []byte {
	dst = append(dst, '"')
	const digits = "0123456789abcdef"
	for _, value := range src {
		switch value {
		case '"', '\\':
			dst = append(dst, '\\', value)
		case '\n':
			dst = append(dst, `\n`...)
		case '\r':
			dst = append(dst, `\r`...)
		case '\t':
			dst = append(dst, `\t`...)
		default:
			if value < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', digits[value>>4], digits[value&0xf])
			} else {
				dst = append(dst, value)
			}
		}
	}
	return append(dst, '"')
}

func dodHexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}
