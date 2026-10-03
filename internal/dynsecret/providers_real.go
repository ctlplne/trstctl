// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/redisacl"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	defaultDynsecretPrefix = "trstctl"
	awsIAMService          = "iam"
)

var (
	errAWSIAMAlreadyExists = errors.New("dynsecret aws-iam: entity already exists")
	errAWSIAMMissing       = errors.New("dynsecret aws-iam: entity not found")
	errPostgresRoleCreate  = errors.New("dynsecret postgres: create role failed")
	errMySQLUserCreate     = errors.New("dynsecret mysql: create user failed")
	errMongoUserCreate     = errors.New("dynsecret mongodb: create user failed")
	errRedisRejected       = errors.New("dynsecret redis: server rejected command")
	errRedisProtocol       = errors.New("dynsecret redis: invalid server response")
)

// HTTPDoer is the minimal HTTP client seam used by cloud dynamic-secret backends.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// SQLExecutor is the database/sql-compatible seam used by the MySQL backend.
type SQLExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// MongoRole describes one MongoDB role assignment for a generated user.
type MongoRole struct {
	Role string
	DB   string
}

// MongoAdmin is the MongoDB user-management seam. Production adapters wire this
// to the official MongoDB driver; tests and emulators can satisfy it directly.
type MongoAdmin interface {
	CreateUser(ctx context.Context, db, user string, password []byte, roles []MongoRole) error
	DropUser(ctx context.Context, db, user string) error
}

// PostgresConfig configures a PostgreSQL dynamic-secret backend.
type PostgresConfig struct {
	DSN            []byte
	Database       string
	Schema         string
	UsernamePrefix string
}

// PostgresBackend creates scoped PostgreSQL login roles and revokes them.
type PostgresBackend struct {
	dsn            *secret.Buffer
	database       string
	schema         string
	usernamePrefix string
}

// NewPostgresBackend builds a PostgreSQL dynamic-secret backend.
func NewPostgresBackend(cfg PostgresConfig) (*PostgresBackend, error) {
	// A file: DSN commonly has the line ending added by the tool that wrote
	// it. PostgreSQL URI syntax does not include that terminator. Remove only
	// terminal CR/LF bytes; keep all other credential bytes unchanged.
	cfg.DSN = bytes.TrimRight(cfg.DSN, "\r\n")
	if len(cfg.DSN) == 0 {
		return nil, errors.New("dynsecret postgres: DSN required")
	}
	if cfg.Database == "" {
		cfg.Database = postgresDatabaseFromDSN(cfg.DSN)
	}
	if cfg.Database == "" {
		cfg.Database = "postgres"
	}
	if cfg.Schema == "" {
		cfg.Schema = "public"
	}
	if cfg.UsernamePrefix == "" {
		cfg.UsernamePrefix = defaultDynsecretPrefix
	}
	dsn, err := secret.NewFrom(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("dynsecret postgres: lock DSN: %w", err)
	}
	return &PostgresBackend{
		dsn:            dsn,
		database:       cfg.Database,
		schema:         cfg.Schema,
		usernamePrefix: cfg.UsernamePrefix,
	}, nil
}

// Create implements Backend.
func (b *PostgresBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role, TTL: 24 * time.Hour})
}

// CreateCredential creates a PostgreSQL role whose native validity is bounded by
// the requested lease TTL. LeaseID makes the role name stable across a worker
// retry after an interrupted response.
func (b *PostgresBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	user, err := scopedNameForRequest(b.usernamePrefix, req, 63, "_")
	if err != nil {
		return "", nil, err
	}
	if req.LeaseID != "" {
		// A pending lease may be resumed after the provider succeeded but before
		// the issued event committed. The lost password cannot be recovered, so
		// deterministically replace that same role before minting a new one.
		if err := b.Revoke(ctx, user); err != nil {
			return "", nil, fmt.Errorf("dynsecret postgres: clean interrupted role: %w", err)
		}
	}
	password, err := randomSecretHex(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)

	conn, err := connectPostgresAdmin(ctx, b.dsn.Bytes())
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = conn.Close(ctx) }()

	ttl := req.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	validUntil := time.Now().UTC().Add(ttl).Format("2006-01-02 15:04:05Z")
	if err := createPostgresRole(ctx, conn, user, password, validUntil); err != nil {
		_ = b.Revoke(ctx, user)
		return "", nil, errPostgresRoleCreate
	}
	stmts := []string{
		"GRANT CONNECT ON DATABASE " + pgQuoteIdent(b.database) + " TO " + pgQuoteIdent(user),
		"GRANT USAGE ON SCHEMA " + pgQuoteIdent(b.schema) + " TO " + pgQuoteIdent(user),
	}
	if readonlyRole(req.Role) {
		stmts = append(stmts, "GRANT SELECT ON ALL TABLES IN SCHEMA "+pgQuoteIdent(b.schema)+" TO "+pgQuoteIdent(user))
	} else {
		stmts = append(stmts, "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA "+pgQuoteIdent(b.schema)+" TO "+pgQuoteIdent(user))
	}
	for _, stmt := range stmts {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			_ = b.Revoke(ctx, user)
			return "", nil, fmt.Errorf("dynsecret postgres: create role %s: %w", user, err)
		}
	}
	secretDSN, err := postgresCredentialDSN(b.dsn.Bytes(), user, password)
	if err != nil {
		_ = b.Revoke(ctx, user)
		return "", nil, err
	}
	return user, secretDSN, nil
}

func (b *PostgresBackend) Close() {
	if b.dsn != nil {
		b.dsn.Destroy()
		b.dsn = nil
	}
}

// Revoke implements Backend.
func (b *PostgresBackend) Revoke(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	conn, err := connectPostgresAdmin(ctx, b.dsn.Bytes())
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(ctx) }()

	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1)`, ref).Scan(&exists); err != nil {
		return fmt.Errorf("dynsecret postgres: lookup role: %w", err)
	}
	if !exists {
		return nil
	}
	_, _ = conn.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename=$1`, ref)
	if _, err := conn.Exec(ctx, "DROP OWNED BY "+pgQuoteIdent(ref)); err != nil {
		return fmt.Errorf("dynsecret postgres: drop owned: %w", err)
	}
	if _, err := conn.Exec(ctx, "DROP ROLE IF EXISTS "+pgQuoteIdent(ref)); err != nil {
		return fmt.Errorf("dynsecret postgres: drop role: %w", err)
	}
	return nil
}

// MySQLConfig configures a MySQL or MariaDB dynamic-secret backend.
type MySQLConfig struct {
	Database                 string
	Addr                     string
	AccountHost              string
	AllowWildcardAccountHost bool
	// Host is the legacy dial address. The MySQL account host must be explicit
	// so a missing scope cannot silently become the global % matcher.
	Host           string
	UsernamePrefix string
}

// MySQLBackend creates scoped MySQL users through a database/sql-compatible executor.
type MySQLBackend struct {
	exec           SQLExecutor
	database       string
	addr           string
	accountHost    string
	usernamePrefix string
}

// NewMySQLBackend builds a MySQL dynamic-secret backend.
func NewMySQLBackend(exec SQLExecutor, cfg MySQLConfig) (*MySQLBackend, error) {
	if exec == nil {
		return nil, errors.New("dynsecret mysql: executor required")
	}
	if cfg.Database == "" {
		return nil, errors.New("dynsecret mysql: Database required")
	}
	if cfg.Addr == "" {
		cfg.Addr = cfg.Host
		if cfg.Addr == "%" {
			// Legacy tests/config used Host only for the SQL account matcher.
			// Keep that source-compatible while production validation requires an
			// explicit reachable Addr.
			cfg.Addr = "localhost:3306"
		}
	}
	if strings.TrimSpace(cfg.AccountHost) == "" {
		return nil, errors.New("dynsecret mysql: AccountHost required")
	}
	if strings.ContainsAny(cfg.AccountHost, "%_") && !cfg.AllowWildcardAccountHost {
		return nil, errors.New("dynsecret mysql: wildcard AccountHost requires AllowWildcardAccountHost")
	}
	if cfg.Addr == "" || cfg.Addr == "%" {
		return nil, errors.New("dynsecret mysql: Addr must name a reachable server")
	}
	if cfg.UsernamePrefix == "" {
		cfg.UsernamePrefix = defaultDynsecretPrefix
	}
	return &MySQLBackend{exec: exec, database: cfg.Database, addr: cfg.Addr, accountHost: cfg.AccountHost, usernamePrefix: cfg.UsernamePrefix}, nil
}

// Create implements Backend.
func (b *MySQLBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

func (b *MySQLBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	user, err := scopedNameForRequest(b.usernamePrefix, req, 32, "_")
	if err != nil {
		return "", nil, err
	}
	if req.LeaseID != "" {
		if err := b.Revoke(ctx, user); err != nil {
			return "", nil, fmt.Errorf("dynsecret mysql: clean interrupted user: %w", err)
		}
	}
	password, err := randomSecretHex(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)

	account := mysqlAccount(user, b.accountHost)
	if err := createMySQLUser(ctx, b.exec, account, password); err != nil {
		// database/sql drivers may include bind values in their errors. Never return
		// an error that can retain the generated password as an immutable string.
		return "", nil, errMySQLUserCreate
	}
	privileges := "SELECT"
	if !readonlyRole(req.Role) {
		privileges = "SELECT, INSERT, UPDATE, DELETE"
	}
	if _, err := b.exec.ExecContext(ctx, "GRANT "+privileges+" ON "+mysqlQuoteIdent(b.database)+".* TO "+account); err != nil {
		_ = b.Revoke(ctx, user)
		return "", nil, fmt.Errorf("dynsecret mysql: grant: %w", err)
	}
	return user, mysqlCredential(b.database, b.addr, user, password), nil
}

// Revoke implements Backend.
func (b *MySQLBackend) Revoke(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	if _, err := b.exec.ExecContext(ctx, "DROP USER IF EXISTS "+mysqlAccount(ref, b.accountHost)); err != nil {
		return fmt.Errorf("dynsecret mysql: drop user: %w", err)
	}
	return nil
}

// MongoConfig configures a MongoDB dynamic-secret backend.
type MongoConfig struct {
	Database       string
	URI            []byte
	UsernamePrefix string
}

// MongoBackend creates scoped MongoDB database users through MongoAdmin.
type MongoBackend struct {
	admin          MongoAdmin
	database       string
	uri            *secret.Buffer
	usernamePrefix string
}

// NewMongoBackend builds a MongoDB dynamic-secret backend.
func NewMongoBackend(admin MongoAdmin, cfg MongoConfig) (*MongoBackend, error) {
	if admin == nil {
		return nil, errors.New("dynsecret mongodb: admin required")
	}
	if cfg.Database == "" {
		return nil, errors.New("dynsecret mongodb: Database required")
	}
	if cfg.UsernamePrefix == "" {
		cfg.UsernamePrefix = defaultDynsecretPrefix
	}
	// The same normalized URI feeds the one-shot admin connection and the
	// workload credential; a file terminator must not enter the issued URI.
	cfg.URI = bytes.TrimRight(cfg.URI, "\r\n")
	var uri *secret.Buffer
	var err error
	if len(cfg.URI) > 0 {
		uri, err = secret.NewFrom(cfg.URI)
		if err != nil {
			return nil, fmt.Errorf("dynsecret mongodb: lock URI: %w", err)
		}
	}
	return &MongoBackend{admin: admin, database: cfg.Database, uri: uri, usernamePrefix: cfg.UsernamePrefix}, nil
}

// Create implements Backend.
func (b *MongoBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

func (b *MongoBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	user, err := scopedNameForRequest(b.usernamePrefix, req, 128, "_")
	if err != nil {
		return "", nil, err
	}
	if req.LeaseID != "" {
		if err := b.Revoke(ctx, user); err != nil {
			return "", nil, fmt.Errorf("dynsecret mongodb: clean interrupted user: %w", err)
		}
	}
	password, err := randomSecretHex(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	mongoRole := "read"
	if !readonlyRole(req.Role) {
		mongoRole = "readWrite"
	}
	if err := b.admin.CreateUser(ctx, b.database, user, password, []MongoRole{{Role: mongoRole, DB: b.database}}); err != nil {
		// A third-party adapter may echo its command on failure. Collapse it to a
		// closed error before it can escape with the generated password.
		return "", nil, errMongoUserCreate
	}
	var uri []byte
	if b.uri != nil {
		uri = b.uri.Bytes()
	}
	return user, mongoCredential(uri, b.database, user, password), nil
}

func (b *MongoBackend) Close() {
	if b.uri != nil {
		b.uri.Destroy()
		b.uri = nil
	}
}

// Revoke implements Backend.
func (b *MongoBackend) Revoke(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	if err := b.admin.DropUser(ctx, b.database, ref); err != nil && !looksMissing(err) {
		return fmt.Errorf("dynsecret mongodb: drop user: %w", err)
	}
	return nil
}

// RedisConfig configures a Redis ACL dynamic-secret backend.
type RedisConfig struct {
	Addr           string
	Password       []byte
	DB             int
	UsernamePrefix string
	RolePolicies   map[string]redisacl.Role
	TLSCAPEM       []byte
	TLSServerName  string
	AllowPlaintext bool
}

// RedisBackend creates Redis ACL users by speaking RESP to Redis.
type RedisBackend struct {
	addr           string
	password       *secret.Buffer
	db             int
	usernamePrefix string
	roleRules      map[string][]string
	dialer         net.Dialer
	tlsCA          []byte
	tlsServerName  string
	allowPlaintext bool
}

// NewRedisBackend builds a Redis dynamic-secret backend.
func NewRedisBackend(cfg RedisConfig) (*RedisBackend, error) {
	if cfg.Addr == "" {
		return nil, errors.New("dynsecret redis: Addr required")
	}
	if len(cfg.Password) == 0 {
		return nil, errors.New("dynsecret redis: admin password required")
	}
	if cfg.DB != 0 {
		return nil, errors.New("dynsecret redis: DB must be 0 because Redis ACLs cannot scope SELECT")
	}
	if cfg.AllowPlaintext {
		host, _, err := net.SplitHostPort(cfg.Addr)
		address := net.ParseIP(host)
		if err != nil || address == nil || (!address.IsLoopback() && !address.IsPrivate()) || cfg.TLSServerName != "" || len(cfg.TLSCAPEM) > 0 {
			return nil, errors.New("dynsecret redis: plaintext is allowed only to a literal private IP without TLS settings")
		}
	} else if cfg.TLSServerName == "" {
		return nil, errors.New("dynsecret redis: verified TLS server name required")
	}
	if len(cfg.RolePolicies) == 0 {
		return nil, errors.New("dynsecret redis: explicit role policies required")
	}
	roleRules := make(map[string][]string, len(cfg.RolePolicies))
	for name, policy := range cfg.RolePolicies {
		if name == "" {
			return nil, errors.New("dynsecret redis: empty role name")
		}
		rules, err := redisacl.Compile(policy)
		if err != nil {
			return nil, fmt.Errorf("dynsecret redis: role %q: %w", name, err)
		}
		roleRules[name] = rules
	}
	if cfg.UsernamePrefix == "" {
		cfg.UsernamePrefix = defaultDynsecretPrefix
	}
	var password *secret.Buffer
	var err error
	if len(cfg.Password) > 0 {
		password, err = secret.NewFrom(cfg.Password)
		if err != nil {
			return nil, fmt.Errorf("dynsecret redis: lock password: %w", err)
		}
	}
	return &RedisBackend{addr: cfg.Addr, password: password, db: cfg.DB, usernamePrefix: cfg.UsernamePrefix,
		roleRules: roleRules, tlsCA: append([]byte(nil), cfg.TLSCAPEM...), tlsServerName: cfg.TLSServerName,
		allowPlaintext: cfg.AllowPlaintext}, nil
}

// Create implements Backend.
func (b *RedisBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

func (b *RedisBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	rules, allowed := b.roleRules[req.Role]
	if !allowed {
		return "", nil, errors.New("dynsecret redis: role has no explicit ACL policy")
	}
	user, err := scopedNameForRequest(b.usernamePrefix, req, 64, "_")
	if err != nil {
		return "", nil, err
	}
	if req.LeaseID != "" {
		if err := b.Revoke(ctx, user); err != nil {
			return "", nil, fmt.Errorf("dynsecret redis: clean interrupted user: %w", err)
		}
	}
	password, err := randomSecretHex(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	passArg := append([]byte{'>'}, password...)
	defer secret.Wipe(passArg)
	command := [][]byte{
		[]byte("ACL"), []byte("SETUSER"), []byte(user), []byte("reset"),
		[]byte("on"), passArg, []byte("resetkeys"), []byte("resetchannels"),
	}
	for _, rule := range rules {
		command = append(command, []byte(rule))
	}
	// PING lets clients probe the connection. SELECT is intentionally absent:
	// Redis ACLs cannot constrain its database argument, so granting it would
	// let a lease access matching key prefixes in every logical database.
	command = append(command, []byte("+ping"))
	if err := b.redisCommands(ctx, command); err != nil {
		return "", nil, err
	}
	// ACL users are otherwise only in Redis memory, even when AOF is enabled.
	// A lease is not active until its exact authority survives a Redis restart.
	if err := b.redisCommands(ctx, [][]byte{[]byte("ACL"), []byte("SAVE")}); err != nil {
		_ = b.Revoke(ctx, user)
		return "", nil, fmt.Errorf("dynsecret redis: persist user ACL: %w", err)
	}
	return user, redisCredential(b.addr, b.db, user, password, !b.allowPlaintext), nil
}

func (b *RedisBackend) Close() {
	if b.password != nil {
		b.password.Destroy()
		b.password = nil
	}
}

// Revoke implements Backend.
func (b *RedisBackend) Revoke(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	if err := b.redisCommands(ctx, [][]byte{[]byte("ACL"), []byte("DELUSER"), []byte(ref)}); err != nil {
		return err
	}
	if err := b.redisCommands(ctx, [][]byte{[]byte("ACL"), []byte("SAVE")}); err != nil {
		return fmt.Errorf("dynsecret redis: persist user revocation: %w", err)
	}
	return nil
}

// KubernetesConfig configures a Kubernetes ServiceAccount token backend.
type KubernetesConfig struct {
	Endpoint       string
	HTTPClient     HTTPDoer
	Namespace      string
	Audience       string
	BearerToken    []byte
	UsernamePrefix string
	RoleBindings   map[string]string
}

// KubernetesBackend creates short-lived ServiceAccounts and TokenRequests.
type KubernetesBackend struct {
	endpoint       string
	doer           HTTPDoer
	namespace      string
	audience       string
	bearerToken    *secret.Buffer
	usernamePrefix string
	roleBindings   map[string]string
}

const kubernetesLeaseOwnerLabel = "trstctl.com/lease-name"

type kubernetesProviderRef struct {
	Version           int    `json:"version"`
	Name              string `json:"name"`
	ServiceAccountUID string `json:"service_account_uid"`
	BoundSecretUID    string `json:"bound_secret_uid"`
	RoleBindingUID    string `json:"role_binding_uid,omitempty"`
}

type kubernetesObject struct {
	Metadata struct {
		UID    string            `json:"uid"`
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
}

// NewKubernetesBackend builds a Kubernetes dynamic-secret backend.
func NewKubernetesBackend(cfg KubernetesConfig) (*KubernetesBackend, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("dynsecret kubernetes: Endpoint required")
	}
	if strings.TrimSpace(cfg.Audience) == "" {
		return nil, errors.New("dynsecret kubernetes: one explicit API audience required")
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "default"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if cfg.UsernamePrefix == "" {
		cfg.UsernamePrefix = defaultDynsecretPrefix
	}
	var token *secret.Buffer
	var err error
	if len(cfg.BearerToken) > 0 {
		token, err = secret.NewFrom(cfg.BearerToken)
		if err != nil {
			return nil, fmt.Errorf("dynsecret kubernetes: lock bearer token: %w", err)
		}
	}
	return &KubernetesBackend{
		endpoint:       strings.TrimRight(cfg.Endpoint, "/"),
		doer:           cfg.HTTPClient,
		namespace:      cfg.Namespace,
		audience:       cfg.Audience,
		bearerToken:    token,
		usernamePrefix: cfg.UsernamePrefix,
		roleBindings:   cloneStringMap(cfg.RoleBindings),
	}, nil
}

// Create implements Backend.
func (b *KubernetesBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role, TTL: time.Hour})
}

func (b *KubernetesBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	ttl := req.TTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	if ttl < 10*time.Minute {
		return "", nil, errors.New("dynsecret kubernetes: lease TTL must be at least 10 minutes (TokenRequest minimum)")
	}
	name, err := scopedKubernetesNameForRequest(b.usernamePrefix, req)
	if err != nil {
		return "", nil, err
	}
	var roleKind, roleName string
	if len(b.roleBindings) > 0 {
		roleRef, ok := b.roleBindings[req.Role]
		if !ok || strings.TrimSpace(roleRef) == "" {
			return "", nil, fmt.Errorf("dynsecret kubernetes: role %q has no configured RoleBinding", req.Role)
		}
		roleKind, roleName, ok = strings.Cut(roleRef, "/")
		if !ok || (roleKind != "Role" && roleKind != "ClusterRole") || roleName == "" {
			return "", nil, fmt.Errorf("dynsecret kubernetes: invalid role binding %q", roleRef)
		}
	}
	if req.LeaseID != "" {
		// TokenRequest has no idempotency token. Deleting and recreating the same
		// lease-scoped objects invalidates a token whose response was lost before
		// the issued event committed. Check ownership and UID before deletion.
		if err := b.reconcileInterrupted(ctx, name); err != nil {
			return "", nil, fmt.Errorf("dynsecret kubernetes: reconcile interrupted lease: %w", err)
		}
	}
	owner := map[string]any{"name": name, "namespace": b.namespace, "labels": map[string]string{kubernetesLeaseOwnerLabel: name}}
	ref := kubernetesProviderRef{Version: 1, Name: name}
	cleanupError := func(stage string, cause error) (string, []byte, error) {
		return "", nil, errors.Join(fmt.Errorf("dynsecret kubernetes: %s: %w", stage, cause), b.reconcileInterrupted(ctx, name))
	}
	saPath := "/api/v1/namespaces/" + pathEscape(b.namespace) + "/serviceaccounts"
	body := map[string]any{
		"apiVersion": "v1",
		"kind":       "ServiceAccount",
		"metadata":   owner,
	}
	var serviceAccount kubernetesObject
	if err := b.json(ctx, http.MethodPost, saPath, body, &serviceAccount); err != nil {
		return "", nil, fmt.Errorf("dynsecret kubernetes: create serviceaccount: %w", err)
	}
	ref.ServiceAccountUID = serviceAccount.Metadata.UID
	if ref.ServiceAccountUID == "" {
		return cleanupError("serviceaccount response has no UID", errors.New("cannot safely revoke an unbound object"))
	}
	secretPath := "/api/v1/namespaces/" + pathEscape(b.namespace) + "/secrets"
	var boundSecret kubernetesObject
	secretBody := map[string]any{"apiVersion": "v1", "kind": "Secret", "type": "Opaque", "metadata": owner}
	if err := b.json(ctx, http.MethodPost, secretPath, secretBody, &boundSecret); err != nil {
		return cleanupError("create token-bound secret", err)
	}
	ref.BoundSecretUID = boundSecret.Metadata.UID
	if ref.BoundSecretUID == "" {
		return cleanupError("bound secret response has no UID", errors.New("cannot safely revoke an unbound object"))
	}
	if len(b.roleBindings) > 0 {
		rbPath := "/apis/rbac.authorization.k8s.io/v1/namespaces/" + pathEscape(b.namespace) + "/rolebindings"
		rb := map[string]any{
			"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
			"metadata": owner,
			"subjects": []map[string]string{{"kind": "ServiceAccount", "name": name, "namespace": b.namespace}},
			"roleRef":  map[string]string{"apiGroup": "rbac.authorization.k8s.io", "kind": roleKind, "name": roleName},
		}
		var binding kubernetesObject
		if err := b.json(ctx, http.MethodPost, rbPath, rb, &binding); err != nil {
			return cleanupError("create rolebinding", err)
		}
		ref.RoleBindingUID = binding.Metadata.UID
		if ref.RoleBindingUID == "" {
			return cleanupError("rolebinding response has no UID", errors.New("cannot safely revoke an unbound object"))
		}
	}
	tokenPath := saPath + "/" + pathEscape(name) + "/token"
	var out struct {
		Status struct {
			Token               secret.JSONBytes `json:"token"`
			ExpirationTimestamp time.Time        `json:"expirationTimestamp"`
		} `json:"status"`
	}
	// Closure: the field is nil until the response is decoded below, so a bare
	// defer would capture that nil and wipe nothing (AN-8).
	defer func() { secret.Wipe(out.Status.Token) }()
	tokenReq := map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenRequest",
		"spec": map[string]any{
			"audiences":         []string{b.audience},
			"boundObjectRef":    map[string]string{"apiVersion": "v1", "kind": "Secret", "name": name, "uid": boundSecret.Metadata.UID},
			"expirationSeconds": int64(ttl / time.Second),
		},
	}
	requestedAt := time.Now()
	if err := b.json(ctx, http.MethodPost, tokenPath, tokenReq, &out); err != nil {
		return cleanupError("token request", err)
	}
	if len(out.Status.Token) == 0 {
		return cleanupError("empty token response", errors.New("TokenRequest returned no token"))
	}
	if out.Status.ExpirationTimestamp.IsZero() || out.Status.ExpirationTimestamp.After(requestedAt.Add(ttl+5*time.Second)) || out.Status.ExpirationTimestamp.Before(requestedAt.Add(ttl-30*time.Second)) {
		return cleanupError("TokenRequest response lifetime does not match the lease", errors.New("unexpected token expiration"))
	}
	encodedRef, err := json.Marshal(ref)
	if err != nil {
		return cleanupError("encode provider reference", err)
	}
	return string(encodedRef), bytes.Clone(out.Status.Token), nil
}

func (b *KubernetesBackend) resourcePaths(name string) [3]string {
	base := "/api/v1/namespaces/" + pathEscape(b.namespace)
	roles := "/apis/rbac.authorization.k8s.io/v1/namespaces/" + pathEscape(b.namespace)
	return [3]string{base + "/secrets/" + pathEscape(name), roles + "/rolebindings/" + pathEscape(name), base + "/serviceaccounts/" + pathEscape(name)}
}

func (b *KubernetesBackend) deleteWithUID(ctx context.Context, path, uid string) error {
	if uid == "" {
		return nil
	}
	options := map[string]any{"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": map[string]string{"uid": uid}}
	if err := b.json(ctx, http.MethodDelete, path, options, nil); err != nil && !statusIs(err, http.StatusNotFound) {
		return err
	}
	return nil
}

// reconcileInterrupted runs before an outbox retry and on partial creation.
// It inspects every same-name object before deleting any, then uses each UID
// as an API precondition so a replacement cannot be removed by a race.
func (b *KubernetesBackend) reconcileInterrupted(ctx context.Context, name string) error {
	paths := b.resourcePaths(name)
	var ids [3]string
	for index, path := range paths {
		var object kubernetesObject
		err := b.json(ctx, http.MethodGet, path, nil, &object)
		if statusIs(err, http.StatusNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		if object.Metadata.UID == "" || object.Metadata.Labels[kubernetesLeaseOwnerLabel] != name {
			return fmt.Errorf("resource collision at %s: object is not owned by this lease", path)
		}
		ids[index] = object.Metadata.UID
	}
	for index, path := range paths {
		if err := b.deleteWithUID(ctx, path, ids[index]); err != nil {
			return fmt.Errorf("remove owned %s: %w", path, err)
		}
	}
	return nil
}

// Revoke implements Backend. New leases persist UIDs in the durable provider
// reference. A plain name is a legacy reference issued by older builds; it is
// retained only so an upgrade can retire already-issued credentials.
func (b *KubernetesBackend) Revoke(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	if strings.HasPrefix(ref, "{") {
		var owned kubernetesProviderRef
		if err := json.Unmarshal([]byte(ref), &owned); err != nil || owned.Version != 1 || owned.Name == "" || owned.ServiceAccountUID == "" || owned.BoundSecretUID == "" {
			return errors.New("dynsecret kubernetes: invalid UID-bound provider reference")
		}
		paths := b.resourcePaths(owned.Name)
		for index, uid := range [3]string{owned.BoundSecretUID, owned.RoleBindingUID, owned.ServiceAccountUID} {
			if err := b.deleteWithUID(ctx, paths[index], uid); err != nil {
				return fmt.Errorf("dynsecret kubernetes: delete UID-bound resource %s: %w", paths[index], err)
			}
		}
		return nil
	}
	// Legacy references did not carry UIDs or ownership labels. Their exact
	// generated name remains the only recovery handle for active old leases.
	paths := b.resourcePaths(ref)
	for _, path := range paths {
		if err := b.json(ctx, http.MethodDelete, path, nil, nil); err != nil && !statusIs(err, http.StatusNotFound) {
			return fmt.Errorf("dynsecret kubernetes: delete legacy resource %s: %w", path, err)
		}
	}
	return nil
}

func (b *KubernetesBackend) Close() {
	if b.bearerToken != nil {
		b.bearerToken.Destroy()
		b.bearerToken = nil
	}
}

// AWSIAMConfig configures an AWS IAM dynamic-secret backend.
type AWSIAMConfig struct {
	Endpoint        string
	HTTPClient      HTTPDoer
	Region          string
	AccessKeyID     string
	SecretAccessKey []byte
	SessionToken    []byte
	UsernamePrefix  string
	PolicyARNs      map[string]string
}

// AWSIAMBackend creates IAM users plus access keys and revokes both.
type AWSIAMBackend struct {
	endpoint       string
	host           string
	doer           HTTPDoer
	region         string
	accessKeyID    string
	secretKey      *secret.Buffer
	sessionToken   *secret.Buffer
	usernamePrefix string
	policyARNs     map[string]string
	now            func() time.Time
}

// NewAWSIAMBackend builds an AWS IAM dynamic-secret backend.
func NewAWSIAMBackend(cfg AWSIAMConfig) (*AWSIAMBackend, error) {
	if cfg.Region == "" {
		return nil, errors.New("dynsecret aws-iam: Region required")
	}
	if cfg.AccessKeyID == "" || len(cfg.SecretAccessKey) == 0 {
		return nil, errors.New("dynsecret aws-iam: access key credentials required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://iam.amazonaws.com"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	if cfg.UsernamePrefix == "" {
		cfg.UsernamePrefix = defaultDynsecretPrefix
	}
	secretKey, err := secret.NewFrom(cfg.SecretAccessKey)
	if err != nil {
		return nil, fmt.Errorf("dynsecret aws-iam: lock secret access key: %w", err)
	}
	var sessionToken *secret.Buffer
	if len(cfg.SessionToken) > 0 {
		sessionToken, err = secret.NewFrom(cfg.SessionToken)
		if err != nil {
			secretKey.Destroy()
			return nil, fmt.Errorf("dynsecret aws-iam: lock session token: %w", err)
		}
	}
	b := &AWSIAMBackend{
		doer:           cfg.HTTPClient,
		region:         cfg.Region,
		accessKeyID:    cfg.AccessKeyID,
		secretKey:      secretKey,
		sessionToken:   sessionToken,
		usernamePrefix: cfg.UsernamePrefix,
		now:            time.Now,
		policyARNs:     cloneStringMap(cfg.PolicyARNs),
	}
	b.setEndpoint(cfg.Endpoint)
	return b, nil
}

// Create implements Backend.
func (b *AWSIAMBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role})
}

func (b *AWSIAMBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	user, err := scopedNameForRequest(b.usernamePrefix, req, 64, "_")
	if err != nil {
		return "", nil, err
	}
	policyARN := strings.TrimSpace(b.policyARNs[req.Role])
	if policyARN == "" && len(b.policyARNs) > 0 {
		return "", nil, fmt.Errorf("dynsecret aws-iam: role %q has no configured policy ARN", req.Role)
	}
	if req.LeaseID != "" {
		// IAM's create APIs have no client request token. Reconcile the stable
		// lease-scoped username first so a response/commit crash cannot leave an
		// unknown access key active beside the retry's key.
		if err := b.cleanupStableUser(ctx, user, policyARN); err != nil {
			return "", nil, err
		}
	}
	if _, err := b.call(ctx, map[string]string{"Action": "CreateUser", "UserName": user, "Version": "2010-05-08"}); err != nil {
		if !looksAlreadyExists(err) {
			return "", nil, fmt.Errorf("dynsecret aws-iam: create user: %w", err)
		}
	}
	if policyARN != "" {
		if _, err := b.call(ctx, map[string]string{"Action": "AttachUserPolicy", "UserName": user, "PolicyArn": policyARN, "Version": "2010-05-08"}); err != nil {
			_ = b.Revoke(ctx, user)
			return "", nil, fmt.Errorf("dynsecret aws-iam: attach policy: %w", err)
		}
	}
	raw, err := b.call(ctx, map[string]string{"Action": "CreateAccessKey", "UserName": user, "Version": "2010-05-08"})
	if err != nil {
		_ = b.Revoke(ctx, user)
		return "", nil, fmt.Errorf("dynsecret aws-iam: create access key: %w", err)
	}
	var out struct {
		Result struct {
			AccessKey struct {
				AccessKeyID     string           `xml:"AccessKeyId"`
				SecretAccessKey secret.JSONBytes `xml:"SecretAccessKey"`
			} `xml:"AccessKey"`
		} `xml:"CreateAccessKeyResult"`
	}
	// The closure matters: evaluating the field in the defer statement itself
	// captures the nil slice that exists BEFORE decoding, so the wipe zeroes
	// nothing and the minted secret access key is left in the heap (AN-8).
	defer func() { secret.Wipe(out.Result.AccessKey.SecretAccessKey) }()
	defer secret.Wipe(raw)
	if err := xml.Unmarshal(raw, &out); err != nil {
		_ = b.Revoke(ctx, user)
		return "", nil, fmt.Errorf("dynsecret aws-iam: decode access key: %w", err)
	}
	if out.Result.AccessKey.AccessKeyID == "" || len(out.Result.AccessKey.SecretAccessKey) == 0 {
		_ = b.Revoke(ctx, user)
		return "", nil, errors.New("dynsecret aws-iam: empty access key response")
	}
	ref := user + "/" + out.Result.AccessKey.AccessKeyID + "|" + url.QueryEscape(policyARN)
	secretBytes, err := json.Marshal(struct {
		AccessKeyID     string           `json:"access_key_id"`
		SecretAccessKey secret.JSONBytes `json:"secret_access_key"`
	}{AccessKeyID: out.Result.AccessKey.AccessKeyID, SecretAccessKey: out.Result.AccessKey.SecretAccessKey})
	if err != nil {
		_ = b.Revoke(ctx, ref)
		return "", nil, err
	}
	return ref, secretBytes, nil
}

func (b *AWSIAMBackend) cleanupStableUser(ctx context.Context, user, policyARN string) error {
	raw, err := b.call(ctx, map[string]string{"Action": "ListAccessKeys", "UserName": user, "Version": "2010-05-08"})
	if err != nil {
		if looksMissing(err) {
			return nil
		}
		return fmt.Errorf("dynsecret aws-iam: reconcile access keys: %w", err)
	}
	var listed struct {
		Result struct {
			Metadata []struct {
				AccessKeyID string `xml:"AccessKeyId"`
			} `xml:"AccessKeyMetadata>member"`
		} `xml:"ListAccessKeysResult"`
	}
	if err := xml.Unmarshal(raw, &listed); err != nil {
		return fmt.Errorf("dynsecret aws-iam: decode access key reconciliation: %w", err)
	}
	for _, item := range listed.Result.Metadata {
		if item.AccessKeyID == "" {
			continue
		}
		if _, err := b.call(ctx, map[string]string{"Action": "DeleteAccessKey", "UserName": user, "AccessKeyId": item.AccessKeyID, "Version": "2010-05-08"}); err != nil && !looksMissing(err) {
			return fmt.Errorf("dynsecret aws-iam: reconcile delete access key: %w", err)
		}
	}
	if policyARN != "" {
		if _, err := b.call(ctx, map[string]string{"Action": "DetachUserPolicy", "UserName": user, "PolicyArn": policyARN, "Version": "2010-05-08"}); err != nil && !looksMissing(err) {
			return fmt.Errorf("dynsecret aws-iam: reconcile detach policy: %w", err)
		}
	}
	if _, err := b.call(ctx, map[string]string{"Action": "DeleteUser", "UserName": user, "Version": "2010-05-08"}); err != nil && !looksMissing(err) {
		return fmt.Errorf("dynsecret aws-iam: reconcile delete user: %w", err)
	}
	return nil
}

// Revoke implements Backend.
func (b *AWSIAMBackend) Revoke(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	user, accessKey, policyARN := splitAWSIAMRef(ref)
	if accessKey != "" {
		_, err := b.call(ctx, map[string]string{"Action": "DeleteAccessKey", "UserName": user, "AccessKeyId": accessKey, "Version": "2010-05-08"})
		if err != nil && !looksMissing(err) {
			return fmt.Errorf("dynsecret aws-iam: delete access key: %w", err)
		}
	}
	if policyARN != "" {
		_, err := b.call(ctx, map[string]string{"Action": "DetachUserPolicy", "UserName": user, "PolicyArn": policyARN, "Version": "2010-05-08"})
		if err != nil && !looksMissing(err) {
			return fmt.Errorf("dynsecret aws-iam: detach policy: %w", err)
		}
	}
	_, err := b.call(ctx, map[string]string{"Action": "DeleteUser", "UserName": user, "Version": "2010-05-08"})
	if err != nil && !looksMissing(err) {
		return fmt.Errorf("dynsecret aws-iam: delete user: %w", err)
	}
	return nil
}

func (b *AWSIAMBackend) Close() {
	if b.secretKey != nil {
		b.secretKey.Destroy()
	}
	if b.sessionToken != nil {
		b.sessionToken.Destroy()
	}
	b.secretKey = nil
	b.sessionToken = nil
}

// GCPIAMConfig configures a GCP IAM service-account key backend.
type GCPIAMConfig struct {
	Endpoint            string
	HTTPClient          HTTPDoer
	Project             string
	ServiceAccountEmail string
	BearerToken         []byte
	UsernamePrefix      string
}

// GCPIAMBackend creates and revokes service-account keys.
type GCPIAMBackend struct {
	endpoint            string
	doer                HTTPDoer
	project             string
	serviceAccountEmail string
	bearerToken         *secret.Buffer
}

type gcpPreparedCredential struct {
	PrivateKeyPEM  []byte `json:"private_key_pem"`
	CertificatePEM []byte `json:"certificate_pem"`
}

// PrepareGCPIAMCredential creates the local half of a GCP service-account key.
// The server envelope-seals this value into the pending issuance event/outbox
// before any network call. Retrying the worker therefore uploads/finds the same
// public identity instead of creating another unrecoverable private key.
func PrepareGCPIAMCredential(req GenerateRequest) ([]byte, error) {
	if req.LeaseID == "" || req.TTL <= 0 {
		return nil, errors.New("dynsecret gcp-iam: stable lease id and positive TTL required for preparation")
	}
	privateKey, certificate, err := crypto.GenerateUploadableRSAKeypair(req.TTL)
	if err != nil {
		return nil, fmt.Errorf("dynsecret gcp-iam: prepare uploadable key: %w", err)
	}
	defer secret.Wipe(privateKey)
	prepared, err := json.Marshal(gcpPreparedCredential{PrivateKeyPEM: privateKey, CertificatePEM: certificate})
	if err != nil {
		return nil, fmt.Errorf("dynsecret gcp-iam: encode prepared key: %w", err)
	}
	return prepared, nil
}

// NewGCPIAMBackend builds a GCP IAM dynamic-secret backend.
func NewGCPIAMBackend(cfg GCPIAMConfig) (*GCPIAMBackend, error) {
	if cfg.Project == "" || cfg.ServiceAccountEmail == "" {
		return nil, errors.New("dynsecret gcp-iam: Project and ServiceAccountEmail required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://iam.googleapis.com"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	var token *secret.Buffer
	var err error
	if len(cfg.BearerToken) > 0 {
		token, err = secret.NewFrom(cfg.BearerToken)
		if err != nil {
			return nil, fmt.Errorf("dynsecret gcp-iam: lock bearer token: %w", err)
		}
	}
	return &GCPIAMBackend{
		endpoint:            strings.TrimRight(cfg.Endpoint, "/"),
		doer:                cfg.HTTPClient,
		project:             cfg.Project,
		serviceAccountEmail: cfg.ServiceAccountEmail,
		bearerToken:         token,
	}, nil
}

// Create implements Backend.
func (b *GCPIAMBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	_ = role
	path := "/v1/projects/" + pathEscape(b.project) + "/serviceAccounts/" + b.serviceAccountEmail + "/keys"
	var out struct {
		Name           string           `json:"name"`
		PrivateKeyData secret.JSONBytes `json:"privateKeyData"`
	}
	// Closure: the field is nil until the response is decoded below, so a bare
	// defer would capture that nil and wipe nothing (AN-8).
	defer func() { secret.Wipe(out.PrivateKeyData) }()
	body := map[string]string{
		"privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE",
		"keyAlgorithm":   "KEY_ALG_RSA_2048",
	}
	if err := gcpJSON(ctx, b.doer, b.endpoint, b.tokenBytes(), http.MethodPost, path, body, &out); err != nil {
		return "", nil, fmt.Errorf("dynsecret gcp-iam: create key: %w", err)
	}
	if out.Name == "" || len(out.PrivateKeyData) == 0 {
		return "", nil, errors.New("dynsecret gcp-iam: empty key response")
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(out.PrivateKeyData)))
	n, err := base64.StdEncoding.Decode(decoded, out.PrivateKeyData)
	if err != nil {
		secret.Wipe(decoded)
		return "", nil, fmt.Errorf("dynsecret gcp-iam: decode privateKeyData: %w", err)
	}
	return out.Name, decoded[:n], nil
}

// CreatePreparedCredential idempotently uploads (or finds) the same X.509 public
// key on every retry, then returns the locally-prepared private key in Google
// service-account JSON form. Unlike keys.create, keys.upload gives the worker a
// stable public identity it can reconcile after a response/commit crash.
func (b *GCPIAMBackend) CreatePreparedCredential(ctx context.Context, _ GenerateRequest, prepared []byte) (string, []byte, error) {
	if len(prepared) == 0 {
		return "", nil, errors.New("dynsecret gcp-iam: sealed prepared key required")
	}
	var material gcpPreparedCredential
	if err := json.Unmarshal(prepared, &material); err != nil {
		return "", nil, fmt.Errorf("dynsecret gcp-iam: decode prepared key: %w", err)
	}
	privateKey, err := secret.NewFrom(material.PrivateKeyPEM)
	secret.Wipe(material.PrivateKeyPEM)
	material.PrivateKeyPEM = nil
	if err != nil {
		return "", nil, fmt.Errorf("dynsecret gcp-iam: lock prepared private key: %w", err)
	}
	defer privateKey.Destroy()
	if len(material.CertificatePEM) == 0 {
		return "", nil, errors.New("dynsecret gcp-iam: prepared public certificate is empty")
	}
	keyName, err := b.findUploadedKey(ctx, material.CertificatePEM)
	if err != nil {
		return "", nil, err
	}
	if keyName == "" {
		path := "/v1/projects/" + pathEscape(b.project) + "/serviceAccounts/" + b.serviceAccountEmail + "/keys:upload"
		var out struct {
			Name string `json:"name"`
		}
		body := map[string]string{"publicKeyData": base64.StdEncoding.EncodeToString(material.CertificatePEM)}
		if err := gcpJSON(ctx, b.doer, b.endpoint, b.tokenBytes(), http.MethodPost, path, body, &out); err != nil {
			// A response may have been lost after GCP accepted the exact public
			// key. Reconcile once before surfacing the retryable error.
			keyName, _ = b.findUploadedKey(ctx, material.CertificatePEM)
			if keyName == "" {
				return "", nil, fmt.Errorf("dynsecret gcp-iam: upload prepared key: %w", err)
			}
		} else {
			keyName = out.Name
		}
	}
	if keyName == "" {
		return "", nil, errors.New("dynsecret gcp-iam: upload returned an empty key name")
	}
	keyID := keyName[strings.LastIndex(keyName, "/")+1:]
	credential := marshalGCPServiceAccountCredential(b.project, b.serviceAccountEmail, keyID, privateKey.Bytes())
	return keyName, credential, nil
}

func (b *GCPIAMBackend) findUploadedKey(ctx context.Context, certificatePEM []byte) (string, error) {
	path := "/v1/projects/" + pathEscape(b.project) + "/serviceAccounts/" + b.serviceAccountEmail + "/keys?keyTypes=USER_MANAGED"
	var listed struct {
		Keys []struct {
			Name string `json:"name"`
		} `json:"keys"`
	}
	if err := gcpJSON(ctx, b.doer, b.endpoint, b.tokenBytes(), http.MethodGet, path, nil, &listed); err != nil {
		if statusIs(err, http.StatusNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("dynsecret gcp-iam: list uploaded keys: %w", err)
	}
	for _, candidate := range listed.Keys {
		if candidate.Name == "" {
			continue
		}
		var out struct {
			PublicKeyData string `json:"publicKeyData"`
		}
		getPath := "/v1/" + strings.TrimPrefix(candidate.Name, "/") + "?publicKeyType=TYPE_X509_PEM_FILE"
		if err := gcpJSON(ctx, b.doer, b.endpoint, b.tokenBytes(), http.MethodGet, getPath, nil, &out); err != nil {
			return "", fmt.Errorf("dynsecret gcp-iam: inspect uploaded key: %w", err)
		}
		publicKey, err := base64.StdEncoding.DecodeString(out.PublicKeyData)
		if err != nil {
			return "", fmt.Errorf("dynsecret gcp-iam: decode uploaded public key: %w", err)
		}
		if bytes.Equal(publicKey, certificatePEM) {
			return candidate.Name, nil
		}
	}
	return "", nil
}

// Revoke implements Backend.
func (b *GCPIAMBackend) Revoke(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	if err := gcpJSON(ctx, b.doer, b.endpoint, b.tokenBytes(), http.MethodDelete, "/v1/"+ref, nil, nil); err != nil && !statusIs(err, http.StatusNotFound) {
		return fmt.Errorf("dynsecret gcp-iam: delete key: %w", err)
	}
	return nil
}

func (b *GCPIAMBackend) tokenBytes() []byte {
	if b.bearerToken == nil {
		return nil
	}
	return b.bearerToken.Bytes()
}

func (b *GCPIAMBackend) Close() {
	if b.bearerToken != nil {
		b.bearerToken.Destroy()
		b.bearerToken = nil
	}
}

// AzureEntraConfig configures an Azure Entra application-password backend.
type AzureEntraConfig struct {
	Endpoint            string
	HTTPClient          HTTPDoer
	ApplicationObjectID string
	ApplicationClientID string
	TenantID            string
	BearerToken         []byte
	UsernamePrefix      string
}

// AzureEntraBackend creates and revokes Entra application passwords.
type AzureEntraBackend struct {
	endpoint            string
	doer                HTTPDoer
	applicationObjectID string
	applicationClientID string
	tenantID            string
	bearerToken         *secret.Buffer
}

// NewAzureEntraBackend builds an Azure Entra dynamic-secret backend.
func NewAzureEntraBackend(cfg AzureEntraConfig) (*AzureEntraBackend, error) {
	if cfg.ApplicationObjectID == "" {
		return nil, errors.New("dynsecret azure-entra: ApplicationObjectID required")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://graph.microsoft.com"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}
	var token *secret.Buffer
	var err error
	if len(cfg.BearerToken) > 0 {
		token, err = secret.NewFrom(cfg.BearerToken)
		if err != nil {
			return nil, fmt.Errorf("dynsecret azure-entra: lock bearer token: %w", err)
		}
	}
	return &AzureEntraBackend{
		endpoint:            strings.TrimRight(cfg.Endpoint, "/"),
		doer:                cfg.HTTPClient,
		applicationObjectID: cfg.ApplicationObjectID,
		applicationClientID: cfg.ApplicationClientID,
		tenantID:            cfg.TenantID,
		bearerToken:         token,
	}, nil
}

// Create implements Backend.
func (b *AzureEntraBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	return b.CreateCredential(ctx, GenerateRequest{Role: role, TTL: 24 * time.Hour})
}

func (b *AzureEntraBackend) CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error) {
	displayName := "trstctl-" + sanitizeFragment(req.Role, "role")
	if req.LeaseID != "" {
		displayName = "trstctl-" + sanitizeFragment(req.LeaseID, "lease")
		if err := b.removePasswordsByDisplayName(ctx, displayName); err != nil {
			return "", nil, err
		}
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	path := "/v1.0/applications/" + pathEscape(b.applicationObjectID) + "/addPassword"
	body := map[string]any{"passwordCredential": map[string]any{
		"displayName": displayName,
		"endDateTime": time.Now().UTC().Add(ttl).Format(time.RFC3339),
	}}
	var out struct {
		KeyID      string           `json:"keyId"`
		SecretText secret.JSONBytes `json:"secretText"`
	}
	// Closure: the field is nil until the response is decoded below, so a bare
	// defer would capture that nil and wipe nothing (AN-8).
	defer func() { secret.Wipe(out.SecretText) }()
	if err := azureJSON(ctx, b.doer, b.endpoint, b.tokenBytes(), http.MethodPost, path, body, &out); err != nil {
		return "", nil, fmt.Errorf("dynsecret azure-entra: add password: %w", err)
	}
	if out.KeyID == "" || len(out.SecretText) == 0 {
		return "", nil, errors.New("dynsecret azure-entra: empty password response")
	}
	credential, err := json.Marshal(struct { // #nosec G117 -- the dynamic-secret provider's minted credential payload; returning it is the API (CWE-200)
		TenantID     string           `json:"tenant_id"`
		ClientID     string           `json:"client_id"`
		ClientSecret secret.JSONBytes `json:"client_secret"`
	}{TenantID: b.tenantID, ClientID: b.applicationClientID, ClientSecret: out.SecretText})
	if err != nil {
		_ = b.Revoke(ctx, out.KeyID)
		return "", nil, err
	}
	return out.KeyID, credential, nil
}

func (b *AzureEntraBackend) removePasswordsByDisplayName(ctx context.Context, displayName string) error {
	path := "/v1.0/applications/" + pathEscape(b.applicationObjectID) + "?$select=passwordCredentials"
	var out struct {
		PasswordCredentials []struct {
			KeyID       string `json:"keyId"`
			DisplayName string `json:"displayName"`
		} `json:"passwordCredentials"`
	}
	if err := azureJSON(ctx, b.doer, b.endpoint, b.tokenBytes(), http.MethodGet, path, nil, &out); err != nil {
		return fmt.Errorf("dynsecret azure-entra: reconcile password credentials: %w", err)
	}
	for _, item := range out.PasswordCredentials {
		if item.DisplayName != displayName || item.KeyID == "" {
			continue
		}
		removePath := "/v1.0/applications/" + pathEscape(b.applicationObjectID) + "/removePassword"
		if err := azureJSON(ctx, b.doer, b.endpoint, b.tokenBytes(), http.MethodPost, removePath, map[string]string{"keyId": item.KeyID}, nil); err != nil && !statusIs(err, http.StatusNotFound) {
			return fmt.Errorf("dynsecret azure-entra: reconcile remove password: %w", err)
		}
	}
	return nil
}

func (b *AzureEntraBackend) tokenBytes() []byte {
	if b.bearerToken == nil {
		return nil
	}
	return b.bearerToken.Bytes()
}

func (b *AzureEntraBackend) Close() {
	if b.bearerToken != nil {
		b.bearerToken.Destroy()
		b.bearerToken = nil
	}
}

// Revoke implements Backend.
func (b *AzureEntraBackend) Revoke(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	path := "/v1.0/applications/" + pathEscape(b.applicationObjectID) + "/removePassword"
	if err := azureJSON(ctx, b.doer, b.endpoint, b.tokenBytes(), http.MethodPost, path, map[string]string{"keyId": ref}, nil); err != nil && !statusIs(err, http.StatusNotFound) {
		return fmt.Errorf("dynsecret azure-entra: remove password: %w", err)
	}
	return nil
}

func randomSecretHex(n int) ([]byte, error) {
	raw, err := crypto.RandomBytes(n)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(raw)
	out := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(out, raw)
	return out, nil
}

func randomNameSuffix() (string, error) {
	raw, err := crypto.RandomBytes(5)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(raw)
	return hex.EncodeToString(raw), nil
}

func scopedName(prefix, role string, max int, sep string) (string, error) {
	suffix, err := randomNameSuffix()
	if err != nil {
		return "", err
	}
	return scopedNameWithSuffix(prefix, role, suffix, max, sep)
}

func scopedNameForRequest(prefix string, req GenerateRequest, max int, sep string) (string, error) {
	if strings.TrimSpace(req.LeaseID) == "" {
		return scopedName(prefix, req.Role, max, sep)
	}
	// The stable suffix makes a crash retry converge on the same external
	// principal instead of leaking one random user per attempt.
	suffix := crypto.SHA256Hex([]byte(req.LeaseID))[:10]
	return scopedNameWithSuffix(prefix, req.Role, suffix, max, sep)
}

func scopedNameWithSuffix(prefix, role, suffix string, max int, sep string) (string, error) {
	prefix = sanitizeFragment(prefix, defaultDynsecretPrefix)
	role = sanitizeFragment(role, "role")
	base := prefix + sep + role
	if max > 0 {
		limit := max - len(sep) - len(suffix)
		if limit < 1 {
			return "", fmt.Errorf("dynsecret: max username length %d too short", max)
		}
		if len(base) > limit {
			base = strings.TrimRight(base[:limit], sep)
			if base == "" {
				base = prefix[:min(len(prefix), limit)]
			}
		}
	}
	return base + sep + suffix, nil
}

func sanitizeFragment(v, fallback string) string {
	var b strings.Builder
	lastSep := false
	for _, r := range strings.ToLower(v) {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastSep = false
			continue
		}
		if !lastSep {
			b.WriteByte('_')
			lastSep = true
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return fallback
	}
	return out
}

func scopedKubernetesNameForRequest(prefix string, req GenerateRequest) (string, error) {
	name, err := scopedNameForRequest(prefix, req, 63, "-")
	if err != nil {
		return "", err
	}
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.Trim(name, "-")
	if name == "" {
		return "", errors.New("dynsecret kubernetes: generated empty name")
	}
	return name, nil
}

func readonlyRole(role string) bool {
	return role == "" || strings.Contains(strings.ToLower(role), "read")
}

func pgQuoteIdent(v string) string {
	return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
}

func pgQuoteLiteral(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "''") + "'"
}

func postgresDatabaseFromDSN(dsn []byte) string {
	if _, _, authorityEnd, _, ok := splitURIAuthority(dsn); ok {
		pathStart := authorityEnd
		if pathStart >= len(dsn) || dsn[pathStart] != '/' {
			return ""
		}
		pathEnd := indexURIPathEnd(dsn, pathStart)
		if pathEnd <= pathStart+1 {
			return ""
		}
		decoded, ok := percentDecode(dsn[pathStart+1 : pathEnd])
		if !ok {
			return ""
		}
		return string(decoded)
	}
	tokens, err := parsePGConnTokens(dsn)
	if err != nil {
		return ""
	}
	for _, token := range tokens {
		if bytes.EqualFold(token.key, []byte("dbname")) {
			value, ok := decodePGConnValue(token.raw)
			if !ok {
				return ""
			}
			return string(value)
		}
	}
	return ""
}

func postgresCredentialDSN(adminDSN []byte, user string, password []byte) ([]byte, error) {
	scheme, authorityStart, authorityEnd, hostStart, ok := splitURIAuthority(adminDSN)
	if ok && (bytes.EqualFold(scheme, []byte("postgres")) || bytes.EqualFold(scheme, []byte("postgresql"))) {
		if hostStart >= authorityEnd {
			return nil, errors.New("dynsecret postgres: DSN host required")
		}
		out := make([]byte, 0, len(adminDSN)+len(user)+len(password)+4)
		out = append(out, adminDSN[:authorityStart]...)
		out = appendURIUserinfo(out, user, password)
		out = append(out, '@')
		out = append(out, adminDSN[hostStart:authorityEnd]...)
		out = appendPostgresURISuffix(out, adminDSN[authorityEnd:])
		return out, nil
	}

	tokens, err := parsePGConnTokens(adminDSN)
	if err != nil {
		return nil, errors.New("dynsecret postgres: invalid keyword DSN")
	}
	out := make([]byte, 0, len(adminDSN)+len(user)+len(password)+24)
	for _, token := range tokens {
		if postgresAuthParameter(token.key) {
			continue
		}
		if len(out) > 0 {
			out = append(out, ' ')
		}
		out = append(out, token.raw...)
	}
	if len(out) > 0 {
		out = append(out, ' ')
	}
	out = append(out, "user="...)
	out = appendPGConnValue(out, []byte(user))
	out = append(out, " password="...)
	out = appendPGConnValue(out, password)
	return out, nil
}

func mysqlQuoteIdent(v string) string {
	return "`" + strings.ReplaceAll(v, "`", "``") + "`"
}

func mysqlQuoteString(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `'`, `''`)
	return "'" + v + "'"
}

func mysqlAccount(user, host string) string {
	return mysqlQuoteString(user) + "@" + mysqlQuoteString(host)
}

func mysqlCredential(database, host, user string, password []byte) []byte {
	out := make([]byte, 0, len(user)+len(password)+len(host)+len(database)+9)
	out = append(out, user...)
	out = append(out, ':')
	out = append(out, password...)
	out = append(out, "@tcp("...)
	out = append(out, host...)
	out = append(out, ")/"...)
	return append(out, database...)
}

func mongoCredential(adminURI []byte, database, user string, password []byte) []byte {
	raw := adminURI
	if len(raw) == 0 {
		raw = []byte("mongodb://localhost/")
	}
	scheme, authorityStart, authorityEnd, hostStart, ok := splitURIAuthority(raw)
	if !ok || (!bytes.EqualFold(scheme, []byte("mongodb")) && !bytes.EqualFold(scheme, []byte("mongodb+srv"))) || hostStart >= authorityEnd {
		raw = []byte("mongodb://localhost/")
		_, authorityStart, authorityEnd, hostStart, _ = splitURIAuthority(raw)
	}
	query := uriQuery(raw, authorityEnd)
	out := make([]byte, 0, len(raw)+len(user)+len(password)+len(database)+16)
	out = append(out, raw[:authorityStart]...)
	out = appendURIUserinfo(out, user, password)
	out = append(out, '@')
	out = append(out, raw[hostStart:authorityEnd]...)
	out = append(out, '/')
	out = appendPercentEncoded(out, []byte(database))
	// A generated user is scoped to database. Preserve non-auth connection
	// options but replace the operator's authSource with the workload database.
	out = appendMongoQuery(out, query, database)
	return out
}

type pgConnToken struct {
	key []byte
	raw []byte
}

func splitURIAuthority(raw []byte) (scheme []byte, authorityStart, authorityEnd, hostStart int, ok bool) {
	marker := bytes.Index(raw, []byte("://"))
	if marker <= 0 {
		return nil, 0, 0, 0, false
	}
	authorityStart = marker + 3
	authorityEnd = len(raw)
	for i := authorityStart; i < len(raw); i++ {
		if raw[i] == '/' || raw[i] == '?' || raw[i] == '#' {
			authorityEnd = i
			break
		}
	}
	hostStart = authorityStart
	if at := bytes.LastIndexByte(raw[authorityStart:authorityEnd], '@'); at >= 0 {
		hostStart = authorityStart + at + 1
	}
	return raw[:marker], authorityStart, authorityEnd, hostStart, true
}

func indexURIPathEnd(raw []byte, start int) int {
	for i := start; i < len(raw); i++ {
		if raw[i] == '?' || raw[i] == '#' {
			return i
		}
	}
	return len(raw)
}

func uriQuery(raw []byte, start int) []byte {
	for i := start; i < len(raw); i++ {
		switch raw[i] {
		case '#':
			return nil
		case '?':
			end := len(raw)
			if fragment := bytes.IndexByte(raw[i+1:], '#'); fragment >= 0 {
				end = i + 1 + fragment
			}
			return raw[i+1 : end]
		}
	}
	return nil
}

func appendURIUserinfo(dst []byte, user string, password []byte) []byte {
	dst = appendPercentEncoded(dst, []byte(user))
	dst = append(dst, ':')
	return appendPercentEncoded(dst, password)
}

func appendPercentEncoded(dst, value []byte) []byte {
	const digits = "0123456789ABCDEF"
	for _, b := range value {
		if isURIUnreserved(b) {
			dst = append(dst, b)
			continue
		}
		dst = append(dst, '%', digits[b>>4], digits[b&0x0f])
	}
	return dst
}

func isURIUnreserved(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
		b == '-' || b == '.' || b == '_' || b == '~'
}

func percentDecode(value []byte) ([]byte, bool) {
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			out = append(out, value[i])
			continue
		}
		if i+2 >= len(value) {
			return nil, false
		}
		hi, okHi := hexNibble(value[i+1])
		lo, okLo := hexNibble(value[i+2])
		if !okHi || !okLo {
			return nil, false
		}
		out = append(out, hi<<4|lo)
		i += 2
	}
	return out, true
}

func hexNibble(b byte) (byte, bool) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', true
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, true
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, true
	default:
		return 0, false
	}
}

func parsePGConnTokens(dsn []byte) ([]pgConnToken, error) {
	var out []pgConnToken
	for i := 0; i < len(dsn); {
		for i < len(dsn) && isASCIISpace(dsn[i]) {
			i++
		}
		if i == len(dsn) {
			break
		}
		start := i
		keyStart := i
		for i < len(dsn) && !isASCIISpace(dsn[i]) && dsn[i] != '=' {
			i++
		}
		keyEnd := i
		for i < len(dsn) && isASCIISpace(dsn[i]) {
			i++
		}
		if keyEnd == keyStart || i >= len(dsn) || dsn[i] != '=' {
			return nil, errors.New("invalid PostgreSQL keyword DSN")
		}
		i++
		for i < len(dsn) && isASCIISpace(dsn[i]) {
			i++
		}
		if i < len(dsn) && dsn[i] == '\'' {
			i++
			closed := false
			for i < len(dsn) {
				if dsn[i] == '\\' && i+1 < len(dsn) {
					i += 2
					continue
				}
				if dsn[i] == '\'' {
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				return nil, errors.New("unterminated PostgreSQL keyword DSN value")
			}
		} else {
			for i < len(dsn) && !isASCIISpace(dsn[i]) {
				if dsn[i] == '\\' && i+1 < len(dsn) {
					i += 2
					continue
				}
				i++
			}
		}
		out = append(out, pgConnToken{key: dsn[keyStart:keyEnd], raw: dsn[start:i]})
	}
	return out, nil
}

func decodePGConnValue(raw []byte) ([]byte, bool) {
	equals := bytes.IndexByte(raw, '=')
	if equals < 0 {
		return nil, false
	}
	value := bytes.TrimSpace(raw[equals+1:])
	quoted := len(value) > 0 && value[0] == '\''
	if quoted {
		if len(value) < 2 || value[len(value)-1] != '\'' {
			return nil, false
		}
		value = value[1 : len(value)-1]
	}
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) {
			i++
		}
		out = append(out, value[i])
	}
	return out, true
}

func appendPGConnValue(dst, value []byte) []byte {
	dst = append(dst, '\'')
	for _, b := range value {
		if b == '\\' || b == '\'' {
			dst = append(dst, '\\')
		}
		dst = append(dst, b)
	}
	return append(dst, '\'')
}

func appendPostgresURISuffix(dst, suffix []byte) []byte {
	queryStart := bytes.IndexByte(suffix, '?')
	if queryStart < 0 {
		return append(dst, suffix...)
	}
	dst = append(dst, suffix[:queryStart]...)
	queryEnd := len(suffix)
	if fragment := bytes.IndexByte(suffix[queryStart+1:], '#'); fragment >= 0 {
		queryEnd = queryStart + 1 + fragment
	}
	query := suffix[queryStart+1 : queryEnd]
	wrote := false
	for len(query) > 0 {
		part := query
		if amp := bytes.IndexByte(query, '&'); amp >= 0 {
			part, query = query[:amp], query[amp+1:]
		} else {
			query = nil
		}
		key := part
		if equals := bytes.IndexByte(part, '='); equals >= 0 {
			key = part[:equals]
		}
		if len(part) == 0 || postgresAuthParameter(key) {
			continue
		}
		if !wrote {
			dst = append(dst, '?')
		} else {
			dst = append(dst, '&')
		}
		dst = append(dst, part...)
		wrote = true
	}
	return append(dst, suffix[queryEnd:]...)
}

func postgresAuthParameter(key []byte) bool {
	for _, sensitive := range [][]byte{
		[]byte("user"), []byte("password"), []byte("passfile"), []byte("sslpassword"),
		[]byte("sslcert"), []byte("sslkey"), []byte("service"), []byte("servicefile"),
	} {
		if bytes.EqualFold(key, sensitive) {
			return true
		}
	}
	return false
}

func isASCIISpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

func appendMongoQuery(dst, query []byte, database string) []byte {
	dst = append(dst, '?')
	wrote := false
	for len(query) > 0 {
		part := query
		if amp := bytes.IndexByte(query, '&'); amp >= 0 {
			part, query = query[:amp], query[amp+1:]
		} else {
			query = nil
		}
		key := part
		if equals := bytes.IndexByte(part, '='); equals >= 0 {
			key = part[:equals]
		}
		if len(part) == 0 || mongoAuthQueryKey(key) {
			continue
		}
		if wrote {
			dst = append(dst, '&')
		}
		dst = append(dst, part...)
		wrote = true
	}
	if wrote {
		dst = append(dst, '&')
	}
	dst = append(dst, "authSource="...)
	return appendPercentEncoded(dst, []byte(database))
}

func mongoAuthQueryKey(key []byte) bool {
	for _, sensitive := range [][]byte{
		[]byte("authSource"), []byte("authMechanism"), []byte("authMechanismProperties"),
		[]byte("proxyPassword"),
	} {
		if bytes.EqualFold(key, sensitive) {
			return true
		}
	}
	return containsASCIIFold(key, []byte("password")) ||
		containsASCIIFold(key, []byte("token")) ||
		containsASCIIFold(key, []byte("secret")) ||
		containsASCIIFold(key, []byte("credential"))
}

func marshalGCPServiceAccountCredential(project, email, keyID string, privateKey []byte) []byte {
	out := make([]byte, 0, len(privateKey)+512)
	out = append(out, `{"type":"service_account","project_id":`...)
	out = appendJSONSecretBytes(out, []byte(project))
	out = append(out, `,"private_key_id":`...)
	out = appendJSONSecretBytes(out, []byte(keyID))
	out = append(out, `,"private_key":`...)
	out = appendJSONSecretBytes(out, privateKey)
	out = append(out, `,"client_email":`...)
	out = appendJSONSecretBytes(out, []byte(email))
	out = append(out, `,"token_uri":"https://oauth2.googleapis.com/token"}`...)
	return out
}

// appendJSONSecretBytes quotes bytes directly so private key material never
// becomes an immutable Go string while constructing a provider credential.
func appendJSONSecretBytes(dst, src []byte) []byte {
	dst = append(dst, '"')
	const hexDigits = "0123456789abcdef"
	for _, value := range src {
		switch value {
		case '"', '\\':
			dst = append(dst, '\\', value)
		case '\b':
			dst = append(dst, `\b`...)
		case '\f':
			dst = append(dst, `\f`...)
		case '\n':
			dst = append(dst, `\n`...)
		case '\r':
			dst = append(dst, `\r`...)
		case '\t':
			dst = append(dst, `\t`...)
		default:
			if value < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[value>>4], hexDigits[value&0xf])
			} else {
				dst = append(dst, value)
			}
		}
	}
	return append(dst, '"')
}

func redisCredential(addr string, db int, user string, password []byte, verifiedTLS bool) []byte {
	out := make([]byte, 0, len(addr)+len(user)+len(password)+24)
	if verifiedTLS {
		out = append(out, "rediss://"...)
	} else {
		out = append(out, "redis://"...)
	}
	out = appendURIUserinfo(out, user, password)
	out = append(out, '@')
	out = append(out, addr...)
	out = append(out, '/')
	return strconv.AppendInt(out, int64(db), 10)
}

func (b *RedisBackend) redisCommands(ctx context.Context, command [][]byte) error {
	var conn net.Conn
	var err error
	if b.allowPlaintext {
		conn, err = b.dialer.DialContext(ctx, "tcp", b.addr)
	} else {
		conn, err = mtls.DialVerifiedTCP(ctx, b.addr, b.tlsServerName, b.tlsCA)
	}
	if err != nil {
		return fmt.Errorf("dynsecret redis: dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(15 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("dynsecret redis: deadline: %w", err)
	}
	reader := bufio.NewReader(conn)
	if b.password != nil && b.password.Len() > 0 {
		if err := redisWriteArray(conn, [][]byte{[]byte("AUTH"), b.password.Bytes()}); err != nil {
			return fmt.Errorf("dynsecret redis: auth write: %w", err)
		}
		if err := redisReadOK(reader); err != nil {
			return fmt.Errorf("dynsecret redis: auth: %w", err)
		}
	}
	if err := redisWriteArray(conn, command); err != nil {
		return fmt.Errorf("dynsecret redis: write: %w", err)
	}
	if err := redisReadOK(reader); err != nil {
		return fmt.Errorf("dynsecret redis: command: %w", err)
	}
	return nil
}

func redisWriteArray(w io.Writer, args [][]byte) error {
	total := 16
	for _, arg := range args {
		total += len(arg) + 16
	}
	buf := make([]byte, 0, total)
	buf = append(buf, '*')
	buf = strconv.AppendInt(buf, int64(len(args)), 10)
	buf = append(buf, '\r', '\n')
	for _, arg := range args {
		buf = append(buf, '$')
		buf = strconv.AppendInt(buf, int64(len(arg)), 10)
		buf = append(buf, '\r', '\n')
		buf = append(buf, arg...)
		buf = append(buf, '\r', '\n')
	}
	defer secret.Wipe(buf)
	for written := 0; written < len(buf); {
		n, err := w.Write(buf[written:])
		if err != nil {
			return err
		}
		if n <= 0 || n > len(buf)-written {
			return io.ErrShortWrite
		}
		written += n
	}
	return nil
}

func redisReadOK(r *bufio.Reader) error {
	prefix, err := r.ReadByte()
	if err != nil {
		return errRedisProtocol
	}
	line, err := r.ReadSlice('\n')
	defer secret.Wipe(line)
	if err != nil {
		return errRedisProtocol
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return errRedisProtocol
	}
	switch prefix {
	case '+', ':':
		return nil
	case '-':
		return errRedisRejected
	default:
		return errRedisProtocol
	}
}

func (b *KubernetesBackend) json(ctx context.Context, method, path string, in any, out any) error {
	var token []byte
	if b.bearerToken != nil {
		token = b.bearerToken.Bytes()
	}
	return bearerJSON(ctx, b.doer, b.endpoint, token, method, path, in, out)
}

func gcpJSON(ctx context.Context, doer HTTPDoer, endpoint string, token []byte, method, path string, in any, out any) error {
	return bearerJSON(ctx, doer, endpoint, token, method, path, in, out)
}

func azureJSON(ctx context.Context, doer HTTPDoer, endpoint string, token []byte, method, path string, in any, out any) error {
	return bearerJSON(ctx, doer, endpoint, token, method, path, in, out)
}

func bearerJSON(ctx context.Context, doer HTTPDoer, endpoint string, token []byte, method, path string, in any, out any) error {
	var body []byte
	var err error
	if in != nil {
		body, err = json.Marshal(in)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(endpoint, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
		req = cloudhttp.SetBody(req, body)
	}
	if len(token) > 0 {
		req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", token))
	}
	return cloudhttp.JSON(doer, req, out)
}

func statusIs(err error, status int) bool {
	var se *cloudhttp.StatusError
	return errors.As(err, &se) && se.StatusCode == status
}

func pathEscape(v string) string {
	return url.PathEscape(v)
}

func (b *AWSIAMBackend) setEndpoint(endpoint string) {
	b.endpoint = strings.TrimRight(endpoint, "/")
	if u, err := url.Parse(endpoint); err == nil {
		b.host = u.Host
	}
}

func (b *AWSIAMBackend) call(ctx context.Context, params map[string]string) ([]byte, error) {
	return b.callService(ctx, params, awsIAMService)
}

func (b *AWSIAMBackend) callService(ctx context.Context, params map[string]string, service string) ([]byte, error) {
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}
	body := []byte(form.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint+"/", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	b.signV4(req, body, b.now().UTC(), service)
	resp, err := b.doer.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	limit := cloudhttp.MaxBodyBytes
	if resp.StatusCode/100 != 2 {
		limit = cloudhttp.MaxErrorBytes
	}
	raw, err := secret.ReadBounded(resp.Body, limit)
	if resp.StatusCode/100 != 2 {
		defer secret.Wipe(raw)
	}
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		switch {
		case containsASCIIFold(raw, []byte("entityalreadyexists")),
			containsASCIIFold(raw, []byte("already exists")):
			return nil, errAWSIAMAlreadyExists
		case containsASCIIFold(raw, []byte("nosuchentity")),
			containsASCIIFold(raw, []byte("not found")),
			containsASCIIFold(raw, []byte("notfound")):
			return nil, errAWSIAMMissing
		default:
			return nil, &cloudhttp.StatusError{StatusCode: resp.StatusCode}
		}
	}
	return raw, nil
}

// containsASCIIFold classifies a bounded response without converting secret-bearing
// bytes into an immutable string or allocating a lowercase copy.
func containsASCIIFold(body, needle []byte) bool {
	for i := 0; i+len(needle) <= len(body); i++ {
		if bytes.EqualFold(body[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

func (b *AWSIAMBackend) signV4(req *http.Request, body []byte, t time.Time, service string) {
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	if b.sessionToken != nil && b.sessionToken.Len() > 0 {
		req.Header.Set("X-Amz-Security-Token", secrettext.String(b.sessionToken.Bytes()))
	}
	signed := []string{"content-type", "host", "x-amz-date"}
	if b.sessionToken != nil && b.sessionToken.Len() > 0 {
		signed = append(signed, "x-amz-security-token")
	}
	if req.Header.Get("X-Amz-Target") != "" {
		// AWS JSON services dispatch by this header. Include it in the
		// signature so a proxy cannot redirect an authenticated request to
		// another operation after the payload has been signed.
		signed = append(signed, "x-amz-target")
	}
	sort.Strings(signed)
	var canonHeaders strings.Builder
	for _, h := range signed {
		v := strings.TrimSpace(req.Header.Get(h))
		if h == "host" {
			v = b.host
		}
		canonHeaders.WriteString(h + ":" + v + "\n")
	}
	signedHeaders := strings.Join(signed, ";")
	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		"",
		canonHeaders.String(),
		signedHeaders,
		crypto.SHA256Hex(body),
	}, "\n")
	credScope := dateStamp + "/" + b.region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credScope,
		crypto.SHA256Hex([]byte(canonicalRequest)),
	}, "\n")
	kSigning := awsSigV4SigningKey(b.secretKey.Bytes(), dateStamp, b.region, service)
	defer secret.Wipe(kSigning)
	signature := hex.EncodeToString(crypto.HMACSHA256(kSigning, []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 "+
		"Credential="+b.accessKeyID+"/"+credScope+", "+
		"SignedHeaders="+signedHeaders+", "+
		"Signature="+signature)
}

func awsSigV4SigningKey(secretAccessKey []byte, dateStamp, region, service string) []byte {
	seed := make([]byte, 0, len("AWS4")+len(secretAccessKey))
	seed = append(seed, "AWS4"...)
	seed = append(seed, secretAccessKey...)
	kDate := crypto.HMACSHA256(seed, []byte(dateStamp))
	secret.Wipe(seed)
	kRegion := crypto.HMACSHA256(kDate, []byte(region))
	secret.Wipe(kDate)
	kService := crypto.HMACSHA256(kRegion, []byte(service))
	secret.Wipe(kRegion)
	kSigning := crypto.HMACSHA256(kService, []byte("aws4_request"))
	secret.Wipe(kService)
	return kSigning
}

func splitAWSIAMRef(ref string) (string, string, string) {
	user, remainder, ok := strings.Cut(ref, "/")
	if !ok {
		return ref, "", ""
	}
	key, encodedPolicy, _ := strings.Cut(remainder, "|")
	policy, _ := url.QueryUnescape(encodedPolicy)
	return user, key, policy
}

func looksMissing(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errAWSIAMMissing) {
		return true
	}
	var se *cloudhttp.StatusError
	if errors.As(err, &se) && se.StatusCode == http.StatusNotFound {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "not found") || strings.Contains(s, "notfound") || strings.Contains(s, "no such") || strings.Contains(s, "nosuchentity")
}

func looksAlreadyExists(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errAWSIAMAlreadyExists) {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "already exists") || strings.Contains(text, "entityalreadyexists") || strings.Contains(text, "conflict")
}

func cloneStringMap(source map[string]string) map[string]string {
	if len(source) == 0 {
		return nil
	}
	out := make(map[string]string, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}
