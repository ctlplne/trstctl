// SPDX-License-Identifier: MPL-2.0

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

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/cloudhttp"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secrettext"
)

const (
	defaultDynsecretPrefix = "trstctl"
	awsIAMService          = "iam"
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
	dsn            []byte
	database       string
	schema         string
	usernamePrefix string
}

// NewPostgresBackend builds a PostgreSQL dynamic-secret backend.
func NewPostgresBackend(cfg PostgresConfig) (*PostgresBackend, error) {
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
	return &PostgresBackend{
		dsn:            secrettext.Clone(cfg.DSN),
		database:       cfg.Database,
		schema:         cfg.Schema,
		usernamePrefix: cfg.UsernamePrefix,
	}, nil
}

// Create implements Backend.
func (b *PostgresBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	user, err := scopedName(b.usernamePrefix, role, 63, "_")
	if err != nil {
		return "", nil, err
	}
	password, err := randomSecretHex(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)

	conn, err := pgx.Connect(ctx, secrettext.String(b.dsn))
	if err != nil {
		return "", nil, fmt.Errorf("dynsecret postgres: connect: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	validUntil := time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02 15:04:05Z")
	stmts := []string{
		"CREATE ROLE " + pgQuoteIdent(user) + " LOGIN PASSWORD " + pgQuoteLiteralBytes(password) + " VALID UNTIL " + pgQuoteLiteral(validUntil),
		"GRANT CONNECT ON DATABASE " + pgQuoteIdent(b.database) + " TO " + pgQuoteIdent(user),
		"GRANT USAGE ON SCHEMA " + pgQuoteIdent(b.schema) + " TO " + pgQuoteIdent(user),
	}
	if readonlyRole(role) {
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
	secretDSN, err := postgresCredentialDSN(b.dsn, user, password)
	if err != nil {
		_ = b.Revoke(ctx, user)
		return "", nil, err
	}
	return user, secretDSN, nil
}

// Revoke implements Backend.
func (b *PostgresBackend) Revoke(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	conn, err := pgx.Connect(ctx, secrettext.String(b.dsn))
	if err != nil {
		return fmt.Errorf("dynsecret postgres: connect revoke: %w", err)
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
	Database       string
	Host           string
	UsernamePrefix string
}

// MySQLBackend creates scoped MySQL users through a database/sql-compatible executor.
type MySQLBackend struct {
	exec           SQLExecutor
	database       string
	host           string
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
	if cfg.Host == "" {
		cfg.Host = "%"
	}
	if cfg.UsernamePrefix == "" {
		cfg.UsernamePrefix = defaultDynsecretPrefix
	}
	return &MySQLBackend{exec: exec, database: cfg.Database, host: cfg.Host, usernamePrefix: cfg.UsernamePrefix}, nil
}

// Create implements Backend.
func (b *MySQLBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	user, err := scopedName(b.usernamePrefix, role, 32, "_")
	if err != nil {
		return "", nil, err
	}
	password, err := randomSecretHex(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)

	account := mysqlAccount(user, b.host)
	if _, err := b.exec.ExecContext(ctx, "CREATE USER "+account+" IDENTIFIED BY "+mysqlQuoteBytes(password)); err != nil {
		return "", nil, fmt.Errorf("dynsecret mysql: create user: %w", err)
	}
	privileges := "SELECT"
	if !readonlyRole(role) {
		privileges = "SELECT, INSERT, UPDATE, DELETE"
	}
	if _, err := b.exec.ExecContext(ctx, "GRANT "+privileges+" ON "+mysqlQuoteIdent(b.database)+".* TO "+account); err != nil {
		_ = b.Revoke(ctx, user)
		return "", nil, fmt.Errorf("dynsecret mysql: grant: %w", err)
	}
	return user, mysqlCredential(b.database, b.host, user, password), nil
}

// Revoke implements Backend.
func (b *MySQLBackend) Revoke(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	if _, err := b.exec.ExecContext(ctx, "DROP USER IF EXISTS "+mysqlAccount(ref, b.host)); err != nil {
		return fmt.Errorf("dynsecret mysql: drop user: %w", err)
	}
	return nil
}

// MongoConfig configures a MongoDB dynamic-secret backend.
type MongoConfig struct {
	Database       string
	UsernamePrefix string
}

// MongoBackend creates scoped MongoDB database users through MongoAdmin.
type MongoBackend struct {
	admin          MongoAdmin
	database       string
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
	return &MongoBackend{admin: admin, database: cfg.Database, usernamePrefix: cfg.UsernamePrefix}, nil
}

// Create implements Backend.
func (b *MongoBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	user, err := scopedName(b.usernamePrefix, role, 128, "_")
	if err != nil {
		return "", nil, err
	}
	password, err := randomSecretHex(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	mongoRole := "read"
	if !readonlyRole(role) {
		mongoRole = "readWrite"
	}
	if err := b.admin.CreateUser(ctx, b.database, user, password, []MongoRole{{Role: mongoRole, DB: b.database}}); err != nil {
		return "", nil, fmt.Errorf("dynsecret mongodb: create user: %w", err)
	}
	return user, mongoCredential(b.database, user, password), nil
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
}

// RedisBackend creates Redis ACL users by speaking RESP to Redis.
type RedisBackend struct {
	addr           string
	password       []byte
	db             int
	usernamePrefix string
	dialer         net.Dialer
}

// NewRedisBackend builds a Redis dynamic-secret backend.
func NewRedisBackend(cfg RedisConfig) (*RedisBackend, error) {
	if cfg.Addr == "" {
		return nil, errors.New("dynsecret redis: Addr required")
	}
	if cfg.UsernamePrefix == "" {
		cfg.UsernamePrefix = defaultDynsecretPrefix
	}
	return &RedisBackend{addr: cfg.Addr, password: secrettext.Clone(cfg.Password), db: cfg.DB, usernamePrefix: cfg.UsernamePrefix}, nil
}

// Create implements Backend.
func (b *RedisBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	user, err := scopedName(b.usernamePrefix, role, 64, "_")
	if err != nil {
		return "", nil, err
	}
	password, err := randomSecretHex(24)
	if err != nil {
		return "", nil, err
	}
	defer secret.Wipe(password)
	capability := "+@read"
	if !readonlyRole(role) {
		capability = "+@all"
	}
	passArg := append([]byte{'>'}, password...)
	defer secret.Wipe(passArg)
	if err := b.redisCommands(ctx, [][]byte{
		[]byte("ACL"), []byte("SETUSER"), []byte(user), []byte("on"), passArg, []byte("~*"), []byte(capability),
	}); err != nil {
		return "", nil, err
	}
	return user, redisCredential(b.addr, b.db, user, password), nil
}

// Revoke implements Backend.
func (b *RedisBackend) Revoke(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	return b.redisCommands(ctx, [][]byte{[]byte("ACL"), []byte("DELUSER"), []byte(ref)})
}

// KubernetesConfig configures a Kubernetes ServiceAccount token backend.
type KubernetesConfig struct {
	Endpoint       string
	HTTPClient     HTTPDoer
	Namespace      string
	BearerToken    []byte
	UsernamePrefix string
}

// KubernetesBackend creates short-lived ServiceAccounts and TokenRequests.
type KubernetesBackend struct {
	endpoint       string
	doer           HTTPDoer
	namespace      string
	bearerToken    []byte
	usernamePrefix string
}

// NewKubernetesBackend builds a Kubernetes dynamic-secret backend.
func NewKubernetesBackend(cfg KubernetesConfig) (*KubernetesBackend, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("dynsecret kubernetes: Endpoint required")
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
	return &KubernetesBackend{
		endpoint:       strings.TrimRight(cfg.Endpoint, "/"),
		doer:           cfg.HTTPClient,
		namespace:      cfg.Namespace,
		bearerToken:    secrettext.Clone(cfg.BearerToken),
		usernamePrefix: cfg.UsernamePrefix,
	}, nil
}

// Create implements Backend.
func (b *KubernetesBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	name, err := scopedKubernetesName(b.usernamePrefix, role)
	if err != nil {
		return "", nil, err
	}
	saPath := "/api/v1/namespaces/" + pathEscape(b.namespace) + "/serviceaccounts"
	body := map[string]any{
		"apiVersion": "v1",
		"kind":       "ServiceAccount",
		"metadata":   map[string]string{"name": name},
	}
	if err := b.json(ctx, http.MethodPost, saPath, body, nil); err != nil && !statusIs(err, http.StatusConflict) {
		return "", nil, fmt.Errorf("dynsecret kubernetes: create serviceaccount: %w", err)
	}
	tokenPath := saPath + "/" + pathEscape(name) + "/token"
	var out struct {
		Status struct {
			Token string `json:"token"`
		} `json:"status"`
	}
	req := map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenRequest",
		"spec":       map[string]int{"expirationSeconds": 3600},
	}
	if err := b.json(ctx, http.MethodPost, tokenPath, req, &out); err != nil {
		_ = b.Revoke(ctx, name)
		return "", nil, fmt.Errorf("dynsecret kubernetes: token request: %w", err)
	}
	if out.Status.Token == "" {
		_ = b.Revoke(ctx, name)
		return "", nil, errors.New("dynsecret kubernetes: empty token response")
	}
	return name, []byte(out.Status.Token), nil
}

// Revoke implements Backend.
func (b *KubernetesBackend) Revoke(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	path := "/api/v1/namespaces/" + pathEscape(b.namespace) + "/serviceaccounts/" + pathEscape(ref)
	if err := b.json(ctx, http.MethodDelete, path, nil, nil); err != nil && !statusIs(err, http.StatusNotFound) {
		return fmt.Errorf("dynsecret kubernetes: delete serviceaccount: %w", err)
	}
	return nil
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
}

// AWSIAMBackend creates IAM users plus access keys and revokes both.
type AWSIAMBackend struct {
	endpoint       string
	host           string
	doer           HTTPDoer
	region         string
	accessKeyID    string
	secretKey      []byte
	sessionToken   []byte
	usernamePrefix string
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
	b := &AWSIAMBackend{
		doer:           cfg.HTTPClient,
		region:         cfg.Region,
		accessKeyID:    cfg.AccessKeyID,
		secretKey:      secrettext.Clone(cfg.SecretAccessKey),
		sessionToken:   secrettext.Clone(cfg.SessionToken),
		usernamePrefix: cfg.UsernamePrefix,
		now:            time.Now,
	}
	b.setEndpoint(cfg.Endpoint)
	return b, nil
}

// Create implements Backend.
func (b *AWSIAMBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	user, err := scopedName(b.usernamePrefix, role, 64, "_")
	if err != nil {
		return "", nil, err
	}
	if _, err := b.call(ctx, map[string]string{"Action": "CreateUser", "UserName": user, "Version": "2010-05-08"}); err != nil {
		return "", nil, fmt.Errorf("dynsecret aws-iam: create user: %w", err)
	}
	raw, err := b.call(ctx, map[string]string{"Action": "CreateAccessKey", "UserName": user, "Version": "2010-05-08"})
	if err != nil {
		_ = b.Revoke(ctx, user)
		return "", nil, fmt.Errorf("dynsecret aws-iam: create access key: %w", err)
	}
	var out struct {
		Result struct {
			AccessKey struct {
				AccessKeyID     string `xml:"AccessKeyId"`
				SecretAccessKey string `xml:"SecretAccessKey"`
			} `xml:"AccessKey"`
		} `xml:"CreateAccessKeyResult"`
	}
	if err := xml.Unmarshal(raw, &out); err != nil {
		_ = b.Revoke(ctx, user)
		return "", nil, fmt.Errorf("dynsecret aws-iam: decode access key: %w", err)
	}
	if out.Result.AccessKey.AccessKeyID == "" || out.Result.AccessKey.SecretAccessKey == "" {
		_ = b.Revoke(ctx, user)
		return "", nil, errors.New("dynsecret aws-iam: empty access key response")
	}
	ref := user + "/" + out.Result.AccessKey.AccessKeyID
	secretBytes, err := json.Marshal(map[string]string{
		"access_key_id":     out.Result.AccessKey.AccessKeyID,
		"secret_access_key": out.Result.AccessKey.SecretAccessKey,
	})
	if err != nil {
		_ = b.Revoke(ctx, ref)
		return "", nil, err
	}
	return ref, secretBytes, nil
}

// Revoke implements Backend.
func (b *AWSIAMBackend) Revoke(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	user, accessKey := splitAWSIAMRef(ref)
	if accessKey != "" {
		_, err := b.call(ctx, map[string]string{"Action": "DeleteAccessKey", "UserName": user, "AccessKeyId": accessKey, "Version": "2010-05-08"})
		if err != nil && !looksMissing(err) {
			return fmt.Errorf("dynsecret aws-iam: delete access key: %w", err)
		}
	}
	_, err := b.call(ctx, map[string]string{"Action": "DeleteUser", "UserName": user, "Version": "2010-05-08"})
	if err != nil && !looksMissing(err) {
		return fmt.Errorf("dynsecret aws-iam: delete user: %w", err)
	}
	return nil
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
	bearerToken         []byte
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
	return &GCPIAMBackend{
		endpoint:            strings.TrimRight(cfg.Endpoint, "/"),
		doer:                cfg.HTTPClient,
		project:             cfg.Project,
		serviceAccountEmail: cfg.ServiceAccountEmail,
		bearerToken:         secrettext.Clone(cfg.BearerToken),
	}, nil
}

// Create implements Backend.
func (b *GCPIAMBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	_ = role
	path := "/v1/projects/" + pathEscape(b.project) + "/serviceAccounts/" + b.serviceAccountEmail + "/keys"
	var out struct {
		Name           string `json:"name"`
		PrivateKeyData string `json:"privateKeyData"`
	}
	body := map[string]string{
		"privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE",
		"keyAlgorithm":   "KEY_ALG_RSA_2048",
	}
	if err := gcpJSON(ctx, b.doer, b.endpoint, b.bearerToken, http.MethodPost, path, body, &out); err != nil {
		return "", nil, fmt.Errorf("dynsecret gcp-iam: create key: %w", err)
	}
	if out.Name == "" || out.PrivateKeyData == "" {
		return "", nil, errors.New("dynsecret gcp-iam: empty key response")
	}
	decoded, err := base64.StdEncoding.DecodeString(out.PrivateKeyData)
	if err != nil {
		return "", nil, fmt.Errorf("dynsecret gcp-iam: decode privateKeyData: %w", err)
	}
	return out.Name, decoded, nil
}

// Revoke implements Backend.
func (b *GCPIAMBackend) Revoke(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	if err := gcpJSON(ctx, b.doer, b.endpoint, b.bearerToken, http.MethodDelete, "/v1/"+ref, nil, nil); err != nil && !statusIs(err, http.StatusNotFound) {
		return fmt.Errorf("dynsecret gcp-iam: delete key: %w", err)
	}
	return nil
}

// AzureEntraConfig configures an Azure Entra application-password backend.
type AzureEntraConfig struct {
	Endpoint            string
	HTTPClient          HTTPDoer
	ApplicationObjectID string
	BearerToken         []byte
	UsernamePrefix      string
}

// AzureEntraBackend creates and revokes Entra application passwords.
type AzureEntraBackend struct {
	endpoint            string
	doer                HTTPDoer
	applicationObjectID string
	bearerToken         []byte
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
	return &AzureEntraBackend{
		endpoint:            strings.TrimRight(cfg.Endpoint, "/"),
		doer:                cfg.HTTPClient,
		applicationObjectID: cfg.ApplicationObjectID,
		bearerToken:         secrettext.Clone(cfg.BearerToken),
	}, nil
}

// Create implements Backend.
func (b *AzureEntraBackend) Create(ctx context.Context, role string) (string, []byte, error) {
	displayName := "trstctl-" + sanitizeFragment(role, "role")
	path := "/v1.0/applications/" + pathEscape(b.applicationObjectID) + "/addPassword"
	body := map[string]any{"passwordCredential": map[string]any{
		"displayName": displayName,
		"endDateTime": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
	}}
	var out struct {
		KeyID      string `json:"keyId"`
		SecretText string `json:"secretText"`
	}
	if err := azureJSON(ctx, b.doer, b.endpoint, b.bearerToken, http.MethodPost, path, body, &out); err != nil {
		return "", nil, fmt.Errorf("dynsecret azure-entra: add password: %w", err)
	}
	if out.KeyID == "" || out.SecretText == "" {
		return "", nil, errors.New("dynsecret azure-entra: empty password response")
	}
	return out.KeyID, []byte(out.SecretText), nil
}

// Revoke implements Backend.
func (b *AzureEntraBackend) Revoke(ctx context.Context, ref string) error {
	if ref == "" {
		return nil
	}
	path := "/v1.0/applications/" + pathEscape(b.applicationObjectID) + "/removePassword"
	if err := azureJSON(ctx, b.doer, b.endpoint, b.bearerToken, http.MethodPost, path, map[string]string{"keyId": ref}, nil); err != nil && !statusIs(err, http.StatusNotFound) {
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

func scopedKubernetesName(prefix, role string) (string, error) {
	name, err := scopedName(prefix, role, 63, "-")
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

func pgQuoteLiteralBytes(v []byte) string {
	return pgQuoteLiteral(secrettext.String(v))
}

func postgresDatabaseFromDSN(dsn []byte) string {
	u, err := url.Parse(secrettext.String(dsn))
	if err != nil || u.Path == "" {
		return ""
	}
	return strings.TrimPrefix(u.Path, "/")
}

func postgresCredentialDSN(adminDSN []byte, user string, password []byte) ([]byte, error) {
	u, err := url.Parse(secrettext.String(adminDSN))
	if err != nil {
		return nil, fmt.Errorf("dynsecret postgres: parse DSN: %w", err)
	}
	if u.Scheme == "postgres" || u.Scheme == "postgresql" {
		u.User = url.UserPassword(user, secrettext.String(password))
		return []byte(u.String()), nil
	}
	return []byte(secrettext.String(adminDSN) + " user=" + user + " password=" + secrettext.String(password)), nil
}

func mysqlQuoteIdent(v string) string {
	return "`" + strings.ReplaceAll(v, "`", "``") + "`"
}

func mysqlQuoteString(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `'`, `''`)
	return "'" + v + "'"
}

func mysqlQuoteBytes(v []byte) string {
	return mysqlQuoteString(secrettext.String(v))
}

func mysqlAccount(user, host string) string {
	return mysqlQuoteString(user) + "@" + mysqlQuoteString(host)
}

func mysqlCredential(database, host, user string, password []byte) []byte {
	return []byte(user + ":" + secrettext.String(password) + "@tcp(" + host + ")/" + database)
}

func mongoCredential(database, user string, password []byte) []byte {
	return []byte("mongodb://" + url.QueryEscape(user) + ":" + url.QueryEscape(secrettext.String(password)) + "@localhost/" + url.PathEscape(database))
}

func redisCredential(addr string, db int, user string, password []byte) []byte {
	u := &url.URL{Scheme: "redis", Host: addr, Path: "/" + strconv.Itoa(db), User: url.UserPassword(user, secrettext.String(password))}
	return []byte(u.String())
}

func (b *RedisBackend) redisCommands(ctx context.Context, command [][]byte) error {
	conn, err := b.dialer.DialContext(ctx, "tcp", b.addr)
	if err != nil {
		return fmt.Errorf("dynsecret redis: dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	if len(b.password) > 0 {
		if err := redisWriteArray(conn, [][]byte{[]byte("AUTH"), b.password}); err != nil {
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
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "*%d\r\n", len(args))
	for _, arg := range args {
		fmt.Fprintf(&buf, "$%d\r\n", len(arg))
		buf.Write(arg)
		buf.WriteString("\r\n")
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func redisReadOK(r *bufio.Reader) error {
	prefix, err := r.ReadByte()
	if err != nil {
		return err
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimSpace(line)
	switch prefix {
	case '+', ':':
		return nil
	case '-':
		if strings.Contains(strings.ToLower(line), "no such user") {
			return nil
		}
		return errors.New(line)
	default:
		return fmt.Errorf("unexpected RESP prefix %q", prefix)
	}
}

func (b *KubernetesBackend) json(ctx context.Context, method, path string, in any, out any) error {
	return bearerJSON(ctx, b.doer, b.endpoint, b.bearerToken, method, path, in, out)
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
	b.signV4(req, body, b.now().UTC())
	resp, err := b.doer.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, cloudhttp.MaxBodyBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, &cloudhttp.StatusError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(raw))}
	}
	return raw, nil
}

func (b *AWSIAMBackend) signV4(req *http.Request, body []byte, t time.Time) {
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	req.Header.Set("X-Amz-Date", amzDate)
	if len(b.sessionToken) > 0 {
		req.Header.Set("X-Amz-Security-Token", secrettext.String(b.sessionToken))
	}
	signed := []string{"content-type", "host", "x-amz-date"}
	if len(b.sessionToken) > 0 {
		signed = append(signed, "x-amz-security-token")
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
	credScope := dateStamp + "/" + b.region + "/" + awsIAMService + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credScope,
		crypto.SHA256Hex([]byte(canonicalRequest)),
	}, "\n")
	kSigning := awsSigV4SigningKey(b.secretKey, dateStamp, b.region, awsIAMService)
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

func splitAWSIAMRef(ref string) (string, string) {
	user, key, ok := strings.Cut(ref, "/")
	if !ok {
		return ref, ""
	}
	return user, key
}

func looksMissing(err error) bool {
	if err == nil {
		return false
	}
	var se *cloudhttp.StatusError
	if errors.As(err, &se) && se.StatusCode == http.StatusNotFound {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "not found") || strings.Contains(s, "notfound") || strings.Contains(s, "no such") || strings.Contains(s, "nosuchentity")
}
