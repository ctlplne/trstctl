// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"trstctl.com/trstctl/internal/redisacl"
)

// The PostgreSQL, MySQL, MongoDB, Redis and AWS IAM backends delete only the
// principals they issued (A240). A static rotation's old_ref that names an
// account its owner provisioned would otherwise have been dropped, with every
// object it owns (PostgreSQL's DROP OWNED); now it is refused before anything
// reaches the target, while an issued name is still revoked.
func TestBackendsRefuseToDeleteWhatTheyDidNotIssue(t *testing.T) {
	ctx := context.Background()
	const foreign = "orders_app"
	issued, err := scopedNameForRequest("trstctl", GenerateRequest{Role: "reader", LeaseID: "lease-1"}, 63, "_")
	if err != nil {
		t.Fatal(err)
	}
	refused := func(name string, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "which this provider did not create") {
			t.Fatalf("%s revoked a principal it did not issue: %v", name, err)
		}
	}

	// Nothing listens on port 1: a dial would fail with a connect error, not
	// the refusal.
	postgres, err := NewPostgresBackend(PostgresConfig{DSN: []byte("postgres://admin:pw@127.0.0.1:1/postgres?sslmode=disable"), UsernamePrefix: "trstctl"})
	if err != nil {
		t.Fatal(err)
	}
	defer postgres.Close()
	refused("postgres", postgres.Revoke(ctx, foreign))
	refused("postgres", postgres.Revoke(ctx, "TRSTCTL_reader_lease")) // the shape needs the 10-hex suffix

	exec := &recordingSQLExec{}
	mysql, err := NewMySQLBackend(exec, MySQLConfig{Database: "app", Addr: "db.internal:3306", AccountHost: "10.0.0.5", UsernamePrefix: "trstctl"})
	if err != nil {
		t.Fatal(err)
	}
	refused("mysql", mysql.Revoke(ctx, foreign))
	if len(exec.queries) != 0 {
		t.Fatalf("mysql sent %v for a refused name", exec.queries)
	}
	if err := mysql.Revoke(ctx, issued); err != nil {
		t.Fatal(err)
	}
	exec.requireContains(t, "DROP USER IF EXISTS")

	admin := &recordingMongoAdmin{created: map[string]bool{}, dropped: map[string]bool{}}
	mongo, err := NewMongoBackend(admin, MongoConfig{Database: "app", UsernamePrefix: "trstctl"})
	if err != nil {
		t.Fatal(err)
	}
	refused("mongodb", mongo.Revoke(ctx, foreign))
	if err := mongo.Revoke(ctx, issued); err != nil || len(admin.dropped) != 1 || !admin.dropped[issued] {
		t.Fatalf("mongodb drops = %v, err %v", admin.dropped, err)
	}

	redis, err := NewRedisBackend(RedisConfig{Addr: "10.255.255.1:1", Password: []byte("operator-admin"), UsernamePrefix: "trstctl", AllowPlaintext: true,
		RolePolicies: map[string]redisacl.Role{"reader": {KeyPrefixes: []string{"cache:"}, Commands: []string{"get"}}}})
	if err != nil {
		t.Fatal(err)
	}
	refused("redis", redis.Revoke(ctx, foreign))

	var calls atomic.Int32
	iam := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer iam.Close()
	aws, err := NewAWSIAMBackend(AWSIAMConfig{Endpoint: iam.URL, HTTPClient: iam.Client(), Region: "us-east-1",
		AccessKeyID: "AKID", SecretAccessKey: []byte("SECRET"), UsernamePrefix: "trstctl"})
	if err != nil {
		t.Fatal(err)
	}
	refused("aws-iam", aws.Revoke(ctx, "deploy-bot/AKIAEXAMPLE"))
	if calls.Load() != 0 {
		t.Fatalf("aws-iam made %d calls for a refused user", calls.Load())
	}
}
