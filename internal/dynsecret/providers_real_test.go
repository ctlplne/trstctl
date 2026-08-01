// SPDX-License-Identifier: MPL-2.0

package dynsecret

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestPostgresBackendCreatesUsableLoginAndRevokes(t *testing.T) {
	ctx := context.Background()
	dsn, stop := startDynsecretPostgres(t)
	defer stop()

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close(ctx) }()
	if _, err := admin.Exec(ctx, `CREATE TABLE IF NOT EXISTS sec04_smoke(id int primary key); INSERT INTO sec04_smoke(id) VALUES (1) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}

	backend, err := NewPostgresBackend(PostgresConfig{DSN: []byte(dsn), Database: "postgres", Schema: "public", UsernamePrefix: "trstctl_test"})
	if err != nil {
		t.Fatal(err)
	}
	ref, secret, err := backend.Create(ctx, "readonly")
	if err != nil {
		t.Fatal(err)
	}
	userConn, err := pgx.Connect(ctx, string(secret))
	if err != nil {
		t.Fatalf("generated credential did not log in: %v", err)
	}
	var got int
	if err := userConn.QueryRow(ctx, `SELECT count(*) FROM public.sec04_smoke`).Scan(&got); err != nil {
		t.Fatalf("generated credential lacks scoped read: %v", err)
	}
	_ = userConn.Close(ctx)
	if got != 1 {
		t.Fatalf("count = %d, want 1", got)
	}
	if err := backend.Revoke(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if err := backend.Revoke(ctx, ref); err != nil {
		t.Fatalf("double revoke must be idempotent: %v", err)
	}
	if conn, err := pgx.Connect(ctx, string(secret)); err == nil {
		_ = conn.Close(ctx)
		t.Fatal("revoked PostgreSQL credential still logs in")
	}
}

func TestGeneratedDatabaseCredentialsStayByteNative(t *testing.T) {
	password := []byte("generated p@ss/?")

	postgresURL, err := postgresCredentialDSN(
		[]byte("postgres://admin:operator-secret@db.internal:5432/app?sslmode=require&sslpassword=query-secret&passfile=/admin/pass"),
		"lease-user", password,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertCredentialPassword(t, postgresURL, "generated p@ss/?")
	for _, forbidden := range [][]byte{[]byte("operator-secret"), []byte("query-secret"), []byte("/admin/pass")} {
		if bytes.Contains(postgresURL, forbidden) {
			t.Fatalf("PostgreSQL workload DSN retained admin authority %q: %q", forbidden, postgresURL)
		}
	}
	if !bytes.Contains(postgresURL, []byte("sslmode=require")) {
		t.Fatalf("PostgreSQL workload DSN lost safe transport option: %q", postgresURL)
	}

	postgresKeyword, err := postgresCredentialDSN(
		[]byte(`host=db.internal dbname='app db' user=admin password='operator secret' passfile='/admin/pass' sslmode=require`),
		"lease-user", password,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte("operator secret"), []byte("/admin/pass"), []byte("user=admin")} {
		if bytes.Contains(postgresKeyword, forbidden) {
			t.Fatalf("PostgreSQL keyword workload DSN retained admin authority %q: %q", forbidden, postgresKeyword)
		}
	}
	if got := postgresDatabaseFromDSN(postgresKeyword); got != "app db" {
		t.Fatalf("keyword DSN database = %q, want app db", got)
	}

	mysql := mysqlCredential("app", "mysql.internal:3306", "lease-user", []byte("generatedhex"))
	if !bytes.Contains(mysql, []byte("lease-user:generatedhex@tcp(mysql.internal:3306)/app")) {
		t.Fatalf("MySQL workload credential = %q", mysql)
	}

	mongo := mongoCredential(
		[]byte("mongodb://admin:operator-secret@mongo.internal:27017/admin?replicaSet=rs0&authSource=admin&authMechanismProperties=AWS_SESSION_TOKEN:operator-token"),
		"app", "lease-user", password,
	)
	assertCredentialPassword(t, mongo, "generated p@ss/?")
	for _, forbidden := range [][]byte{[]byte("operator-secret"), []byte("operator-token"), []byte("authSource=admin")} {
		if bytes.Contains(mongo, forbidden) {
			t.Fatalf("MongoDB workload URI retained admin authority %q: %q", forbidden, mongo)
		}
	}
	if !bytes.Contains(mongo, []byte("replicaSet=rs0")) || !bytes.Contains(mongo, []byte("authSource=app")) {
		t.Fatalf("MongoDB workload URI lost safe routing options: %q", mongo)
	}

	redis := redisCredential("redis.internal:6379", 4, "lease-user", password)
	assertCredentialPassword(t, redis, "generated p@ss/?")
}

func assertCredentialPassword(t *testing.T, credential []byte, want string) {
	t.Helper()
	u, err := url.Parse(string(credential))
	if err != nil {
		t.Fatalf("parse generated credential: %v", err)
	}
	got, ok := u.User.Password()
	if !ok || got != want {
		t.Fatalf("generated credential password = %q, %v; want %q, true", got, ok, want)
	}
}

func TestGeneratedDatabasePasswordErrorsAreClosed(t *testing.T) {
	t.Run("mysql driver echo", func(t *testing.T) {
		exec := &echoingSQLExec{}
		backend, err := NewMySQLBackend(exec, MySQLConfig{Database: "app", Addr: "mysql.internal:3306"})
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = backend.CreateCredential(context.Background(), GenerateRequest{Role: "reader"})
		if !errors.Is(err, errMySQLUserCreate) {
			t.Fatalf("MySQL error = %v, want closed create-user error", err)
		}
		if strings.Contains(err.Error(), "driver echoed") {
			t.Fatalf("MySQL error retained driver echo: %v", err)
		}
		if exec.queryContainsPassword || !strings.Contains(exec.query, "IDENTIFIED BY ?") || len(exec.password) == 0 {
			t.Fatalf("MySQL password binding was not byte-native: query=%q password_len=%d embedded=%v", exec.query, len(exec.password), exec.queryContainsPassword)
		}
	})

	t.Run("mongodb adapter echo", func(t *testing.T) {
		admin := &echoingMongoAdmin{}
		backend, err := NewMongoBackend(admin, MongoConfig{Database: "app"})
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = backend.CreateCredential(context.Background(), GenerateRequest{Role: "reader"})
		if !errors.Is(err, errMongoUserCreate) {
			t.Fatalf("MongoDB error = %v, want closed create-user error", err)
		}
		if strings.Contains(err.Error(), "adapter echoed") || len(admin.password) == 0 {
			t.Fatalf("MongoDB error retained adapter echo or saw no password: error=%v password_len=%d", err, len(admin.password))
		}
	})
}

func TestMongoCreateUserCommandEncodesPasswordWithoutStringConversion(t *testing.T) {
	password := []byte("bson-secret")
	command := mongoCreateUserCommand("lease-user", password, []MongoRole{{Role: "read", DB: "app"}})
	if err := bson.Raw(command).Validate(); err != nil {
		t.Fatalf("raw createUser BSON is invalid: %v", err)
	}
	value, err := bson.Raw(command).LookupErr("pwd")
	if err != nil {
		t.Fatal(err)
	}
	if got := value.StringValue(); got != "bson-secret" {
		t.Fatalf("BSON password = %q", got)
	}
}

func TestRedisResponsesAreBoundedWipedAndClosed(t *testing.T) {
	const echoed = "redis-echoed-secret"
	err := redisReadOK(bufio.NewReader(strings.NewReader("-ERR " + echoed + "\r\n")))
	if !errors.Is(err, errRedisRejected) || strings.Contains(err.Error(), echoed) {
		t.Fatalf("Redis rejection = %v; want closed error without echo", err)
	}
	if err := redisReadOK(bufio.NewReader(strings.NewReader("-ERR no SUCH user " + echoed + "\r\n"))); err != nil {
		t.Fatalf("idempotent missing-user response = %v", err)
	}
	oversized := "-ERR " + strings.Repeat(echoed, 512) + "\r\n"
	err = redisReadOK(bufio.NewReaderSize(strings.NewReader(oversized), 64))
	if !errors.Is(err, errRedisProtocol) || strings.Contains(err.Error(), echoed) {
		t.Fatalf("oversized Redis response = %v; want closed protocol error", err)
	}

	w := &retainingWriter{}
	if err := redisWriteArray(w, [][]byte{[]byte("AUTH"), []byte(echoed)}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(w.last, []byte(echoed)) {
		t.Fatalf("Redis staging buffer retained authority after write: %q", w.last)
	}
	if !allZero(w.last) {
		t.Fatalf("Redis staging buffer was not explicitly wiped: %v", w.last)
	}
}

func TestGeneratedDatabasePasswordCodeDoesNotStringifySecrets(t *testing.T) {
	for _, name := range []string{"providers_real.go", "drivers.go"} {
		source, err := os.ReadFile(name) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{
			"secrettext.String(password)", "string(password)", "url.UserPassword", "ReadString(",
		} {
			if bytes.Contains(source, []byte(forbidden)) {
				t.Errorf("%s contains forbidden generated-secret conversion %q", name, forbidden)
			}
		}
	}
}

func TestConcreteBackendsCreateScopedCredentialAndRevoke(t *testing.T) {
	ctx := context.Background()
	mysql := &recordingSQLExec{}
	mysqlBackend, err := NewMySQLBackend(mysql, MySQLConfig{Database: "app", Host: "%", UsernamePrefix: "trstctl"})
	if err != nil {
		t.Fatal(err)
	}
	mongo := &recordingMongoAdmin{}
	mongoBackend, err := NewMongoBackend(mongo, MongoConfig{Database: "app", UsernamePrefix: "trstctl"})
	if err != nil {
		t.Fatal(err)
	}
	redisSrv := newRESPServer(t)
	redisBackend, err := NewRedisBackend(RedisConfig{Addr: redisSrv.addr, UsernamePrefix: "trstctl"})
	if err != nil {
		t.Fatal(err)
	}
	k8s := newK8sTokenServer(t)
	k8sBackend, err := NewKubernetesBackend(KubernetesConfig{Endpoint: k8s.URL, HTTPClient: k8s.Client(), Namespace: "apps", BearerToken: []byte("sa-token"), UsernamePrefix: "trstctl"})
	if err != nil {
		t.Fatal(err)
	}
	aws := newAWSIAMServer(t)
	awsBackend, err := NewAWSIAMBackend(AWSIAMConfig{Endpoint: aws.URL, HTTPClient: aws.Client(), Region: "us-east-1", AccessKeyID: "AKID", SecretAccessKey: []byte("SECRET"), UsernamePrefix: "trstctl"})
	if err != nil {
		t.Fatal(err)
	}
	gcp := newGCPIAMServer(t)
	gcpBackend, err := NewGCPIAMBackend(GCPIAMConfig{Endpoint: gcp.URL, HTTPClient: gcp.Client(), Project: "p", ServiceAccountEmail: "dyn@p.iam.gserviceaccount.com", BearerToken: []byte("gcp-token"), UsernamePrefix: "trstctl"})
	if err != nil {
		t.Fatal(err)
	}
	azure := newAzureEntraServer(t)
	azureBackend, err := NewAzureEntraBackend(AzureEntraConfig{Endpoint: azure.URL, HTTPClient: azure.Client(), ApplicationObjectID: "app-obj", BearerToken: []byte("az-token"), UsernamePrefix: "trstctl"})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		backend Backend
		assert  func(string)
	}{
		{"mysql", mysqlBackend, func(ref string) {
			mysql.requireContains(t, "CREATE USER")
			mysql.requireContains(t, "GRANT SELECT")
			mysql.requireContains(t, "DROP USER IF EXISTS")
		}},
		{"mongodb", mongoBackend, func(ref string) {
			if !mongo.created[ref] || !mongo.dropped[ref] {
				t.Fatalf("mongo lifecycle not observed for %s: created=%v dropped=%v", ref, mongo.created, mongo.dropped)
			}
		}},
		{"redis", redisBackend, func(ref string) {
			redisSrv.require(t, "ACL SETUSER "+ref)
			redisSrv.require(t, "~* +@read +ping +select")
			redisSrv.reject(t, "+@connection")
			redisSrv.reject(t, "+@all")
			redisSrv.require(t, "ACL DELUSER "+ref)
		}},
		{"kubernetes", k8sBackend, func(ref string) {
			k8s.require(t, http.MethodPost, "/api/v1/namespaces/apps/serviceaccounts")
			k8s.require(t, http.MethodPost, "/api/v1/namespaces/apps/serviceaccounts/"+ref+"/token")
			k8s.require(t, http.MethodDelete, "/api/v1/namespaces/apps/serviceaccounts/"+ref)
		}},
		{"aws-iam", awsBackend, func(ref string) {
			aws.require(t, "CreateUser")
			aws.require(t, "CreateAccessKey")
			aws.require(t, "DeleteAccessKey")
			aws.require(t, "DeleteUser")
		}},
		{"gcp-iam", gcpBackend, func(ref string) {
			gcp.require(t, http.MethodPost, "/v1/projects/p/serviceAccounts/dyn@p.iam.gserviceaccount.com/keys")
			gcp.require(t, http.MethodDelete, "/v1/"+ref)
		}},
		{"azure-entra", azureBackend, func(ref string) {
			azure.require(t, http.MethodPost, "/v1.0/applications/app-obj/addPassword")
			azure.require(t, http.MethodPost, "/v1.0/applications/app-obj/removePassword")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref, secret, err := tc.backend.Create(ctx, "readonly")
			if err != nil {
				t.Fatal(err)
			}
			if ref == "" || len(secret) == 0 {
				t.Fatalf("empty credential: ref=%q secret_len=%d", ref, len(secret))
			}
			if err := tc.backend.Revoke(ctx, ref); err != nil {
				t.Fatal(err)
			}
			if err := tc.backend.Revoke(ctx, ref); err != nil {
				t.Fatalf("double revoke must be idempotent: %v", err)
			}
			tc.assert(ref)
		})
	}
}

func TestGCPIAMPreparedUploadIsIdempotentAcrossWorkerRetry(t *testing.T) {
	ctx := context.Background()
	gcp := newGCPIAMServer(t)
	backend, err := NewGCPIAMBackend(GCPIAMConfig{
		Endpoint: gcp.URL, HTTPClient: gcp.Client(), Project: "p",
		ServiceAccountEmail: "dyn@p.iam.gserviceaccount.com", BearerToken: []byte("gcp-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	req := GenerateRequest{LeaseID: "lease-gcp-stable", Role: "reader", TTL: time.Hour}
	prepared, err := PrepareGCPIAMCredential(req)
	if err != nil {
		t.Fatal(err)
	}
	ref1, credential1, err := backend.CreatePreparedCredential(ctx, req, prepared)
	if err != nil {
		t.Fatal(err)
	}
	ref2, credential2, err := backend.CreatePreparedCredential(ctx, req, prepared)
	if err != nil {
		t.Fatal(err)
	}
	if ref1 == "" || ref1 != ref2 || !bytes.Equal(credential1, credential2) {
		t.Fatalf("prepared retry changed credential: refs=%q/%q", ref1, ref2)
	}
	if got := gcp.count(http.MethodPost, "/v1/projects/p/serviceAccounts/dyn@p.iam.gserviceaccount.com/keys:upload"); got != 1 {
		t.Fatalf("GCP upload calls = %d, want one", got)
	}
}

func TestProviderWorkerRetryReplacesLostAuthorityOnStableIdentity(t *testing.T) {
	ctx := context.Background()
	req := GenerateRequest{LeaseID: "lease-retry-stable", Role: "reader", TTL: time.Hour}

	t.Run("aws iam", func(t *testing.T) {
		remote := newAWSIAMServer(t)
		backend, err := NewAWSIAMBackend(AWSIAMConfig{
			Endpoint: remote.URL, HTTPClient: remote.Client(), Region: "us-east-1",
			AccessKeyID: "AKID", SecretAccessKey: []byte("SECRET"), UsernamePrefix: "trstctl",
		})
		if err != nil {
			t.Fatal(err)
		}
		defer backend.Close()
		ref1, credential1, err := backend.CreateCredential(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		ref2, credential2, err := backend.CreateCredential(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if ref1 == ref2 || bytes.Equal(credential1, credential2) || remote.activeKeys() != 1 {
			t.Fatalf("retry did not replace lost AWS key: refs=%q/%q active=%d", ref1, ref2, remote.activeKeys())
		}
	})

	t.Run("azure entra", func(t *testing.T) {
		remote := newAzureEntraServer(t)
		backend, err := NewAzureEntraBackend(AzureEntraConfig{
			Endpoint: remote.URL, HTTPClient: remote.Client(), ApplicationObjectID: "app-obj",
			ApplicationClientID: "client", TenantID: "tenant", BearerToken: []byte("az-token"),
		})
		if err != nil {
			t.Fatal(err)
		}
		defer backend.Close()
		ref1, credential1, err := backend.CreateCredential(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		ref2, credential2, err := backend.CreateCredential(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if ref1 == ref2 || bytes.Equal(credential1, credential2) || remote.count(http.MethodPost, "/v1.0/applications/app-obj/removePassword") != 1 {
			t.Fatalf("retry did not replace lost Entra password: refs=%q/%q", ref1, ref2)
		}
	})

	t.Run("kubernetes", func(t *testing.T) {
		remote := newK8sTokenServer(t)
		backend, err := NewKubernetesBackend(KubernetesConfig{
			Endpoint: remote.URL, HTTPClient: remote.Client(), Namespace: "apps",
			BearerToken: []byte("sa-token"), UsernamePrefix: "trstctl",
		})
		if err != nil {
			t.Fatal(err)
		}
		defer backend.Close()
		ref1, _, err := backend.CreateCredential(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		ref2, _, err := backend.CreateCredential(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		path := "/api/v1/namespaces/apps/serviceaccounts/" + ref1
		if ref1 != ref2 || remote.count(http.MethodDelete, path) < 2 {
			t.Fatalf("retry did not recreate stable ServiceAccount: refs=%q/%q deletes=%d", ref1, ref2, remote.count(http.MethodDelete, path))
		}
	})
}

// dynsecretShortTempRoot returns a short world-standard temp root so the
// PostgreSQL unix socket path stays under the 108-byte sun_path limit on every
// platform (macOS resolves /tmp to /private/tmp; Linux CI uses /tmp directly).
func dynsecretShortTempRoot() string {
	if runtime.GOOS == "darwin" {
		return "/private/tmp"
	}
	return "/tmp"
}

func startDynsecretPostgres(t *testing.T) (string, func()) {
	t.Helper()
	port := freeDynsecretPort(t)
	dir, err := os.MkdirTemp(dynsecretShortTempRoot(), "trstctl-dynsecret-pg-*")
	if err != nil {
		t.Fatal(err)
	}
	bin := dir + "/bin"
	runtime := dir + "/runtime"
	data := dir + "/data"
	if err := os.MkdirAll(bin, 0o755); err != nil { // #nosec G301 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	if err := os.MkdirAll(runtime, 0o755); err != nil { // #nosec G301 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	if err := os.MkdirAll(data, 0o755); err != nil { // #nosec G301 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatal(err)
	}
	db := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Username("postgres").Password("postgres").Database("postgres").
		Port(uint32(port)).RuntimePath(runtime).DataPath(data).BinariesPath(bin)) // #nosec G115 -- bounded fixture/corpus value packing inside a test (CWE-190)
	if err := db.Start(); err != nil {
		_ = os.RemoveAll(dir)
		fmt.Fprintln(os.Stderr, "embedded postgres start:", err)
		t.Skip("embedded postgres unavailable")
	}
	return fmt.Sprintf("postgres://postgres:postgres@localhost:%d/postgres?sslmode=disable", port), func() {
		_ = db.Stop()
		_ = os.RemoveAll(dir)
	}
}

func freeDynsecretPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

type recordingSQLExec struct {
	mu      sync.Mutex
	queries []string
}

type echoingSQLExec struct {
	query                 string
	password              []byte
	queryContainsPassword bool
}

func (e *echoingSQLExec) ExecContext(_ context.Context, query string, args ...any) (sql.Result, error) {
	e.query = query
	if len(args) > 0 {
		if password, ok := args[0].([]byte); ok {
			e.password = bytes.Clone(password)
			e.queryContainsPassword = strings.Contains(query, string(password))
			return nil, fmt.Errorf("driver echoed %s", password)
		}
	}
	return nil, nil
}

func (r *recordingSQLExec) ExecContext(_ context.Context, q string, _ ...any) (sql.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.queries = append(r.queries, q)
	return nil, nil
}

func (r *recordingSQLExec) requireContains(t *testing.T, want string) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, q := range r.queries {
		if strings.Contains(q, want) {
			return
		}
	}
	t.Fatalf("SQL query containing %q not found in %#v", want, r.queries)
}

type recordingMongoAdmin struct {
	created map[string]bool
	dropped map[string]bool
}

type echoingMongoAdmin struct{ password []byte }

func (e *echoingMongoAdmin) CreateUser(_ context.Context, _, _ string, password []byte, _ []MongoRole) error {
	e.password = bytes.Clone(password)
	return fmt.Errorf("adapter echoed %s", password)
}

func (*echoingMongoAdmin) DropUser(context.Context, string, string) error { return nil }

func (m *recordingMongoAdmin) CreateUser(_ context.Context, db, user string, password []byte, roles []MongoRole) error {
	if m.created == nil {
		m.created = map[string]bool{}
		m.dropped = map[string]bool{}
	}
	if db != "app" || len(password) == 0 || len(roles) == 0 {
		return fmt.Errorf("bad mongo create db=%s roles=%d secret=%d", db, len(roles), len(password))
	}
	m.created[user] = true
	return nil
}

func (m *recordingMongoAdmin) DropUser(_ context.Context, db, user string) error {
	if db != "app" {
		return fmt.Errorf("bad mongo drop db=%s", db)
	}
	m.dropped[user] = true
	return nil
}

type respServer struct {
	addr string
	mu   sync.Mutex
	seen []string
}

type retainingWriter struct{ last []byte }

func (w *retainingWriter) Write(value []byte) (int, error) {
	w.last = value
	return len(value), nil
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func newRESPServer(t *testing.T) *respServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &respServer{addr: ln.Addr().String()}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	return s
}

func (s *respServer) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		cmd := strings.Join(parseRESPArray(string(buf[:n])), " ")
		s.mu.Lock()
		s.seen = append(s.seen, cmd)
		s.mu.Unlock()
		_, _ = c.Write([]byte("+OK\r\n"))
	}
}

func (s *respServer) require(t *testing.T, want string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, got := range s.seen {
		if strings.Contains(got, want) {
			return
		}
	}
	t.Fatalf("RESP command containing %q not found in %#v", want, s.seen)
}

func (s *respServer) reject(t *testing.T, forbidden string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, got := range s.seen {
		if strings.Contains(got, forbidden) {
			t.Fatalf("RESP command unexpectedly contains %q: %q", forbidden, got)
		}
	}
}

func parseRESPArray(raw string) []string {
	lines := strings.Split(raw, "\r\n")
	out := []string{}
	for i := 0; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "$") && i+1 < len(lines) {
			out = append(out, lines[i+1])
			i++
		}
	}
	return out
}

type pathRecorder struct {
	*httptest.Server
	mu    sync.Mutex
	calls []string
}

func (p *pathRecorder) record(r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, r.Method+" "+r.URL.Path)
}

func (p *pathRecorder) require(t *testing.T, method, path string) {
	t.Helper()
	want := method + " " + path
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, got := range p.calls {
		if got == want {
			return
		}
	}
	t.Fatalf("call %q not found in %#v", want, p.calls)
}

func (p *pathRecorder) count(method, path string) int {
	want := method + " " + path
	p.mu.Lock()
	defer p.mu.Unlock()
	count := 0
	for _, got := range p.calls {
		if got == want {
			count++
		}
	}
	return count
}

func newK8sTokenServer(t *testing.T) *pathRecorder {
	t.Helper()
	p := &pathRecorder{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.record(r)
		if r.Header.Get("Authorization") != "Bearer sa-token" {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/serviceaccounts"):
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"metadata":{"name":"ok"}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/token"):
			_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]string{"token": "k8s-token"}})
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.Close)
	return p
}

type awsIAMRecorder struct {
	*httptest.Server
	mu      sync.Mutex
	actions []string
	users   map[string]bool
	keys    map[string]string
	nextKey int
}

func newAWSIAMServer(t *testing.T) *awsIAMRecorder {
	t.Helper()
	a := &awsIAMRecorder{users: map[string]bool{}, keys: map[string]string{}}
	a.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			http.Error(w, "missing sigv4", http.StatusForbidden)
			return
		}
		_ = r.ParseForm()
		action := r.Form.Get("Action")
		a.mu.Lock()
		a.actions = append(a.actions, action)
		switch action {
		case "ListAccessKeys":
			user := r.Form.Get("UserName")
			if !a.users[user] {
				a.mu.Unlock()
				http.Error(w, "NoSuchEntity", http.StatusNotFound)
				return
			}
			members := ""
			for key, owner := range a.keys {
				if owner == user {
					members += "<member><AccessKeyId>" + key + "</AccessKeyId></member>"
				}
			}
			a.mu.Unlock()
			_, _ = w.Write([]byte("<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata>" + members + "</AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>"))
			return
		case "CreateUser":
			a.users[r.Form.Get("UserName")] = true
			a.mu.Unlock()
			_, _ = w.Write([]byte(`<ok/>`))
		case "CreateAccessKey":
			a.nextKey++
			key := fmt.Sprintf("AKIASEC%02d", a.nextKey)
			a.keys[key] = r.Form.Get("UserName")
			a.mu.Unlock()
			_, _ = w.Write([]byte(`<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><AccessKeyId>` + key + `</AccessKeyId><SecretAccessKey>aws-secret-` + key + `</SecretAccessKey></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>`))
		case "DeleteAccessKey":
			delete(a.keys, r.Form.Get("AccessKeyId"))
			a.mu.Unlock()
			_, _ = w.Write([]byte(`<ok/>`))
		case "DeleteUser":
			delete(a.users, r.Form.Get("UserName"))
			a.mu.Unlock()
			_, _ = w.Write([]byte(`<ok/>`))
		case "AttachUserPolicy", "DetachUserPolicy":
			a.mu.Unlock()
			_, _ = w.Write([]byte(`<ok/>`))
		default:
			a.mu.Unlock()
			http.Error(w, "bad action", http.StatusBadRequest)
		}
	}))
	t.Cleanup(a.Close)
	return a
}

func TestAWSIAMErrorBodyIsClassifiedThenDestroyed(t *testing.T) {
	const echoedSecret = "echoed-sensitive-upstream-material"
	for _, tc := range []struct {
		name          string
		status        int
		body          string
		alreadyExists bool
	}{
		{name: "closed semantic error", status: http.StatusConflict, body: `EntityAlreadyExists: ` + echoedSecret, alreadyExists: true},
		{name: "generic status", status: http.StatusBadGateway, body: `upstream: ` + echoedSecret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			backend, err := NewAWSIAMBackend(AWSIAMConfig{
				Endpoint: srv.URL, HTTPClient: srv.Client(), Region: "us-east-1",
				AccessKeyID: "AKID", SecretAccessKey: []byte("SECRET"),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer backend.Close()

			_, err = backend.call(context.Background(), map[string]string{
				"Action": "CreateUser", "UserName": "test", "Version": "2010-05-08",
			})
			if err == nil {
				t.Fatal("expected upstream rejection")
			}
			if got := looksAlreadyExists(err); got != tc.alreadyExists {
				t.Fatalf("looksAlreadyExists = %v, want %v (error %v)", got, tc.alreadyExists, err)
			}
			if strings.Contains(err.Error(), echoedSecret) {
				t.Fatalf("error retained upstream body: %v", err)
			}
		})
	}
}

func (a *awsIAMRecorder) activeKeys() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.keys)
}

func (a *awsIAMRecorder) require(t *testing.T, action string) {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, got := range a.actions {
		if got == action {
			return
		}
	}
	t.Fatalf("AWS action %q not found in %#v", action, a.actions)
}

func newGCPIAMServer(t *testing.T) *pathRecorder {
	t.Helper()
	p := &pathRecorder{}
	certificates := map[string][]byte{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.record(r)
		if r.Header.Get("Authorization") != "Bearer gcp-token" {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/keys") {
			keys := make([]map[string]string, 0, len(certificates))
			for key := range certificates {
				keys = append(keys, map[string]string{"name": "projects/p/serviceAccounts/dyn@p.iam.gserviceaccount.com/keys/" + key})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
			return
		}
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/keys/") {
			key := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			certificate := certificates[key]
			if len(certificate) == 0 {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"publicKeyData": base64.StdEncoding.EncodeToString(certificate)})
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/keys:upload") {
			var body struct {
				PublicKeyData string `json:"publicKeyData"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			certificate, _ := base64.StdEncoding.DecodeString(body.PublicKeyData)
			key := fmt.Sprintf("uploaded-%d", len(certificates)+1)
			certificates[key] = certificate
			_ = json.NewEncoder(w).Encode(map[string]string{"name": "projects/p/serviceAccounts/dyn@p.iam.gserviceaccount.com/keys/" + key})
			return
		}
		if r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"name":           "projects/p/serviceAccounts/dyn@p.iam.gserviceaccount.com/keys/key-1",
				"privateKeyData": base64.StdEncoding.EncodeToString([]byte(`{"client_email":"dyn@p"}`)),
			})
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(p.Close)
	return p
}

func newAzureEntraServer(t *testing.T) *pathRecorder {
	t.Helper()
	p := &pathRecorder{}
	credentials := map[string]string{}
	nextKey := 0
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.record(r)
		if r.Header.Get("Authorization") != "Bearer az-token" {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/applications/") {
			items := make([]map[string]string, 0, len(credentials))
			for key, displayName := range credentials {
				items = append(items, map[string]string{"keyId": key, "displayName": displayName})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"passwordCredentials": items})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/addPassword") {
			var body struct {
				PasswordCredential struct {
					DisplayName string `json:"displayName"`
				} `json:"passwordCredential"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			nextKey++
			key := fmt.Sprintf("key-%d", nextKey)
			credentials[key] = body.PasswordCredential.DisplayName
			_ = json.NewEncoder(w).Encode(map[string]string{"keyId": key, "secretText": "azure-secret-" + key})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/removePassword") {
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			delete(credentials, body["keyId"])
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(p.Close)
	return p
}

// keep imports honest while the red test names the XML and URL protocols the concrete
// providers must speak.
var (
	_ = xml.Name{}
	_ = url.Values{}
)
