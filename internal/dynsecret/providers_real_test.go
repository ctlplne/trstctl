// SPDX-License-Identifier: MPL-2.0

package dynsecret

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"
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

func startDynsecretPostgres(t *testing.T) (string, func()) {
	t.Helper()
	port := freeDynsecretPort(t)
	dir, err := os.MkdirTemp("/private/tmp", "trstctl-dynsecret-pg-*")
	if err != nil {
		t.Fatal(err)
	}
	bin := dir + "/bin"
	runtime := dir + "/runtime"
	data := dir + "/data"
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(runtime, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(data, 0o755); err != nil {
		t.Fatal(err)
	}
	db := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V16).
		Username("postgres").Password("postgres").Database("postgres").
		Port(uint32(port)).RuntimePath(runtime).DataPath(data).BinariesPath(bin))
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
}

func newAWSIAMServer(t *testing.T) *awsIAMRecorder {
	t.Helper()
	a := &awsIAMRecorder{}
	a.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			http.Error(w, "missing sigv4", http.StatusForbidden)
			return
		}
		_ = r.ParseForm()
		action := r.Form.Get("Action")
		a.mu.Lock()
		a.actions = append(a.actions, action)
		a.mu.Unlock()
		switch action {
		case "CreateUser", "DeleteAccessKey", "DeleteUser":
			_, _ = w.Write([]byte(`<ok/>`))
		case "CreateAccessKey":
			_, _ = w.Write([]byte(`<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><AccessKeyId>AKIASEC04</AccessKeyId><SecretAccessKey>aws-secret</SecretAccessKey></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>`))
		default:
			http.Error(w, "bad action", http.StatusBadRequest)
		}
	}))
	t.Cleanup(a.Close)
	return a
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
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.record(r)
		if r.Header.Get("Authorization") != "Bearer gcp-token" {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
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
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.record(r)
		if r.Header.Get("Authorization") != "Bearer az-token" {
			http.Error(w, "missing bearer", http.StatusUnauthorized)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/addPassword") {
			_ = json.NewEncoder(w).Encode(map[string]string{"keyId": "key-1", "secretText": "azure-secret"})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/removePassword") {
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
