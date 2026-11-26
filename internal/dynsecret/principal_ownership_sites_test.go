// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/redisacl"
)

// CR-220: every backend that adopts, re-keys, replaces, deletes or drops an
// existing principal by its derived name now names it with the control plane's
// keyed lease suffix, so the principal it meets under that name is its own.
// One subtest per adoption site proves, with the backend's existing test fake:
//   (a) a lease request without the keyed suffix is refused before any backend
//       operation (the old unkeyed derivation is gone);
//   (b) two leases with different suffixes get different principals, and the
//       second issue sends nothing that names the first one's principal;
//   (c) a retry of the same lease (same suffix) reaches its own principal again;
//   (d) the issued keyed name passes the backend's own revoke gate.
// These are the landed forms of the R1 proof tests
// TestS13b05bL2DistinctLeasesNeverAdoptOnePrincipal (Cassandra, HANA),
// TestVH28DistinctLeasesNeverShareAPrincipalOracleMSSQL,
// TestS13b06aL2DistinctLeasesNeverShareACouchbaseUser and
// TestS13b06bL1DistinctLeasesNeverShareAPrincipal (Kafka, Atlas, Milvus).

// ownershipSiteBackend is the part of a backend the matrix drives.
type ownershipSiteBackend interface {
	CreateCredential(ctx context.Context, req GenerateRequest) (string, []byte, error)
	Revoke(ctx context.Context, ref string) error
}

// ownershipSite builds one backend over a fresh fake and returns its
// operation log so far, one line per operation the backend sent. nameOf, when
// set, maps a reference to the principal's name for backends whose reference
// is a key ID rather than the name.
type ownershipSite struct {
	name   string
	role   string
	setup  func(t *testing.T) (ownershipSiteBackend, func() []string)
	nameOf func(ref string) string
}

func checkOwnershipSite(t *testing.T, site ownershipSite) {
	t.Helper()
	ctx := context.Background()
	b, ops := site.setup(t)
	nameOf := site.nameOf
	if nameOf == nil {
		nameOf = principalOf
	}
	role := site.role
	if role == "" {
		role = "reader"
	}
	leaseA, leaseB := "lease-cr220-site-a", "lease-cr220-site-b"
	reqA := GenerateRequest{Role: role, TTL: 3600_000_000_000, LeaseID: leaseA, PrincipalSuffix: testPrincipalSuffix(leaseA)}
	reqB := GenerateRequest{Role: role, TTL: 3600_000_000_000, LeaseID: leaseB, PrincipalSuffix: testPrincipalSuffix(leaseB)}

	// (a) No keyed suffix: refused before the backend is touched.
	before := len(ops())
	if _, _, err := b.CreateCredential(ctx, GenerateRequest{Role: role, TTL: reqA.TTL, LeaseID: leaseA}); err == nil {
		t.Fatal("a lease without the keyed suffix was issued")
	}
	if after := ops(); len(after) != before {
		t.Fatalf("the refused lease still reached the backend: %q", after[before:])
	}

	// (b) Two leases, two principals; the second issue leaves the first alone.
	refA, _, err := b.CreateCredential(ctx, reqA)
	if err != nil {
		t.Fatalf("issue lease A: %v", err)
	}
	nameA := nameOf(refA)
	aBefore := linesNaming(ops(), nameA)
	refB, _, err := b.CreateCredential(ctx, reqB)
	if err != nil {
		t.Fatalf("issue lease B: %v", err)
	}
	nameB := nameOf(refB)
	if strings.EqualFold(nameA, nameB) {
		t.Fatalf("two leases were issued one principal %q", nameA)
	}
	// Everything the fake holds or logged about lease A's principal is the
	// same after lease B's issue: B sent nothing that named A's principal.
	if aAfter := linesNaming(ops(), nameA); strings.Join(aAfter, "\n") != strings.Join(aBefore, "\n") {
		t.Fatalf("lease B's issue touched lease A's principal %q:\nbefore %q\nafter  %q", nameA, aBefore, aAfter)
	}

	// (c) A retry of lease A reaches lease A's principal again.
	retry, _, err := b.CreateCredential(ctx, reqA)
	if err != nil {
		t.Fatalf("retry lease A: %v", err)
	}
	if !strings.EqualFold(nameOf(retry), nameA) {
		t.Fatalf("a retry of lease A named %q, want its own %q", nameOf(retry), nameA)
	}

	// (d) The keyed name passes the backend's own revoke gate. The retry's
	// reference is the live one (a key backend replaced lease A's key).
	if err := b.Revoke(ctx, retry); err != nil {
		t.Fatalf("revoke lease A's keyed principal %q: %v", retry, err)
	}
}

// linesNaming returns the operation or state lines that name principal, case
// insensitively (some targets upper-case names).
func linesNaming(lines []string, principal string) []string {
	var out []string
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), strings.ToLower(principal)) {
			out = append(out, line)
		}
	}
	return out
}

// snapshot renders a stand-in's per-principal state as sorted lines.
func snapshot[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, fmt.Sprintf("%s=%v", k, v))
	}
	sort.Strings(out)
	return out
}

// snapshotKeys returns m's keys, sorted.
func snapshotKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// principalOf extracts the principal name from a backend reference: some
// backends return the bare name, others a structured or prefixed reference.
func principalOf(ref string) string {
	for _, field := range strings.FieldsFunc(ref, func(r rune) bool { return strings.ContainsRune(`{}",:/ `, r) }) {
		if strings.Contains(field, testPrincipalSuffix("lease-cr220-site-a")[:10]) ||
			strings.Contains(field, testPrincipalSuffix("lease-cr220-site-b")[:10]) ||
			strings.Contains(strings.ToLower(field), testPrincipalSuffix("lease-cr220-site-a")[:10]) ||
			strings.Contains(strings.ToLower(field), testPrincipalSuffix("lease-cr220-site-b")[:10]) {
			return field
		}
	}
	return ref
}

func TestEveryAdoptionSiteOnlyMeetsItsOwnLeasesPrincipalCR220(t *testing.T) {
	for _, site := range []ownershipSite{
		{name: "cassandra", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			fake := &fakeCassandra{}
			return newTestCassandra(t, fake), func() []string { return append([]string(nil), fake.statements...) }
		}},
		{name: "hana", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			fake := &fakeHANA{}
			return newTestHANA(t, fake), func() []string {
				out := make([]string, 0, len(fake.calls))
				for _, c := range fake.calls {
					out = append(out, fmt.Sprint(c.statement, c.args))
				}
				return out
			}
		}},
		{name: "oracle", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			fake := &fakeOracle{}
			return newTestOracle(t, fake), func() []string {
				out := make([]string, 0, len(fake.calls))
				for _, c := range fake.calls {
					out = append(out, fmt.Sprint(c.statement, c.binds))
				}
				return out
			}
		}},
		{name: "sqlserver", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			exec := &recordingMSSQL{}
			b, err := NewMSSQLBackend(exec, MSSQLConfig{Database: "orders", RoleBindings: map[string]string{"reader": "db_datareader"}})
			if err != nil {
				t.Fatal(err)
			}
			return b, func() []string {
				out := make([]string, 0, len(exec.calls))
				for _, c := range exec.calls {
					out = append(out, fmt.Sprint(c.query, c.args))
				}
				return out
			}
		}},
		{name: "kafka", role: "consumer", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			fake := &fakeKafka{scram: map[string]string{}, acls: map[kafkaACLKey]bool{}}
			return newFakeKafkaBackend(t, fake), func() []string { return append(append([]string(nil), fake.calls...), snapshot(fake.scram)...) }
		}},
		{name: "snowflake", role: "analyst", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			adminKey, adminSPKI := snowflakeTestKey(t)
			sf, srv := newSnowflakeStandIn(t, adminSPKI)
			return newLabSnowflake(t, srv, adminKey), func() []string {
				sf.mu.Lock()
				defer sf.mu.Unlock()
				// One line per statement: the log is keyed by the user who sent it.
				var out []string
				for _, sender := range snapshotKeys(sf.sqlByUser) {
					for _, statement := range sf.sqlByUser[sender] {
						out = append(out, sender+": "+statement)
					}
				}
				return append(out, snapshot(sf.keys)...)
			}
		}},
		{name: "rabbitmq", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			lab, srv := newRabbitMQLab(t)
			return newLabRabbitMQ(t, srv), func() []string {
				lab.mu.Lock()
				defer lab.mu.Unlock()
				return append(snapshot(lab.users), snapshot(lab.permissions)...)
			}
		}},
		{name: "clickhouse", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			lab, srv := newClickHouseLab(t)
			return newLabClickHouse(t, srv, time.Now()), func() []string {
				lab.mu.Lock()
				defer lab.mu.Unlock()
				return append([]string(nil), lab.statements...)
			}
		}},
		{name: "couchbase", role: "orders", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			lab, srv := newCouchbaseStandIn(t)
			return newLabCouchbase(t, srv), func() []string {
				lab.mu.Lock()
				defer lab.mu.Unlock()
				return append(append([]string(nil), lab.calls...), snapshot(lab.users)...)
			}
		}},
		{name: "mongodb-atlas", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			lab, srv := newAtlasStandIn(t)
			return newLabAtlas(t, srv, time.Now()), func() []string {
				lab.mu.Lock()
				defer lab.mu.Unlock()
				return append(append([]string(nil), lab.calls...), snapshot(lab.users)...)
			}
		}},
		{name: "milvus", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			lab, srv := newMilvusStandIn(t)
			return newLabMilvus(t, srv, map[string]string{"reader": "orders_reader, audit"}), func() []string {
				lab.mu.Lock()
				defer lab.mu.Unlock()
				return append(append([]string(nil), lab.calls...), snapshot(lab.users)...)
			}
		}},
		{name: "aws-cache-users", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			lab, srv := newAWSCacheStandIn(t, AWSMemoryDB)
			b, err := NewAWSCacheUsersBackend(AWSCacheUsersConfig{
				Service: AWSMemoryDB, Endpoint: srv.URL, Region: "us-east-1", AccessKeyID: "AKIALAB", SecretAccessKey: []byte("lab-secret"),
				UserGroup: "orders-group", RolePolicies: map[string]redisacl.Role{"reader": {KeyPrefixes: []string{"orders:"}, Commands: []string{"get", "hget"}}},
				HTTPClient: srv.Client(), PollInterval: time.Millisecond,
			})
			if err != nil {
				t.Fatal(err)
			}
			return b, func() []string {
				lab.mu.Lock()
				defer lab.mu.Unlock()
				return snapshot(lab.users)
			}
		}},
		{name: "ibm-api-connect", role: "partner", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			lab, srv := newAPIConnectStandIn(t)
			b, err := NewAPIConnectBackend(APIConnectConfig{Endpoint: srv.URL, ClientID: "toolkit", ClientSecret: []byte("toolkit-secret"),
				APIKey: []byte("lab-api-key"), RoleBindings: map[string]string{"partner": apiConnectLabApp}, AllowInsecureLoopback: true, HTTPClient: srv.Client()})
			if err != nil {
				t.Fatal(err)
			}
			return b, func() []string {
				lab.mu.Lock()
				defer lab.mu.Unlock()
				return snapshot(lab.credentials)
			}
		}},
		{name: "mysql", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			exec := &recordingSQLExec{}
			b, err := NewMySQLBackend(exec, MySQLConfig{Database: "app", Addr: "mysql.internal:3306", AccountHost: "10.4.0.12"})
			if err != nil {
				t.Fatal(err)
			}
			return b, func() []string {
				exec.mu.Lock()
				defer exec.mu.Unlock()
				return append([]string(nil), exec.queries...)
			}
		}},
		{name: "mongodb", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			admin := &loggingMongoAdmin{MongoAdmin: &recordingMongoAdmin{created: map[string]bool{}, dropped: map[string]bool{}}}
			b, err := NewMongoBackend(admin, MongoConfig{Database: "app"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(b.Close)
			return b, func() []string { return append([]string(nil), admin.log...) }
		}},
		{name: "redis", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			srv := newRESPServer(t)
			b, err := NewRedisBackend(RedisConfig{Addr: srv.addr, Password: []byte("operator-admin"), UsernamePrefix: "trstctl", AllowPlaintext: true,
				RolePolicies: map[string]redisacl.Role{"reader": {KeyPrefixes: []string{"orders:"}, Commands: []string{"get"}}}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(b.Close)
			return b, func() []string {
				srv.mu.Lock()
				defer srv.mu.Unlock()
				return append([]string(nil), srv.seen...)
			}
		}},
		{name: "ldap", role: "readonly", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			directory := newFakeDirectory()
			return newTestLDAPBackend(t, directory), func() []string {
				var out []string
				for _, dn := range snapshotKeys(directory.entries) {
					out = append(out, "entry "+dn)
				}
				for _, line := range snapshot(directory.passwords) {
					out = append(out, "password "+line)
				}
				for _, group := range snapshotKeys(directory.groups) {
					for _, member := range snapshotKeys(directory.groups[group]) {
						out = append(out, "member "+group+" "+member)
					}
				}
				return out
			}
		}},
		{name: "kubernetes", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			remote := newK8sTokenServer(t)
			b, err := NewKubernetesBackend(KubernetesConfig{Endpoint: remote.URL, HTTPClient: remote.Client(), Namespace: "apps",
				Audience: "https://kubernetes.default.svc", BearerToken: []byte("sa-token"), UsernamePrefix: "trstctl"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(b.Close)
			return b, func() []string {
				remote.mu.Lock()
				defer remote.mu.Unlock()
				return append([]string(nil), remote.calls...)
			}
		}, nameOf: func(ref string) string {
			var owned kubernetesProviderRef
			_ = json.Unmarshal([]byte(ref), &owned)
			return owned.Name
		}},
		{name: "aws-iam", setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			remote := newAWSIAMServer(t)
			b, err := NewAWSIAMBackend(AWSIAMConfig{Endpoint: remote.URL, HTTPClient: remote.Client(), Region: "us-east-1",
				AccessKeyID: "AKID", SecretAccessKey: []byte("SECRET"), UsernamePrefix: "trstctl"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(b.Close)
			return b, func() []string {
				remote.mu.Lock()
				defer remote.mu.Unlock()
				return append(snapshot(remote.users), snapshot(remote.keys)...)
			}
		}, nameOf: func(ref string) string {
			user, _, _ := splitAWSIAMRef(ref)
			return user
		}},
		hostedKeysOwnershipSite(),
		datadogOwnershipSite(),
		openAIOwnershipSite(),
	} {
		t.Run(site.name, func(t *testing.T) { checkOwnershipSite(t, site) })
	}

	// The AWS decoy backend keeps its earlier-release names (decoys are found
	// by them), so it never meets a principal by name alone: a user already
	// under the decoy's name that carries ANOTHER decoy's ownership tag fails
	// the create closed, after reads only, and that user and its key survive.
	t.Run("aws-honeytoken collision", func(t *testing.T) {
		remote := newHoneyIAMFake(t)
		colliding, err := LegacyLeasePrincipalName("qa", "honeytoken", "decoy-1", 64, "_")
		if err != nil {
			t.Fatal(err)
		}
		remote.mu.Lock()
		remote.users[colliding] = "owned-decoy-2"
		remote.keys["AKIADECOY9999"] = colliding
		remote.mu.Unlock()
		b := newHoneyBackendForTest(t, remote) // owner tag owned-decoy-1
		if _, _, err := b.Create(context.Background(), "decoy-1"); err == nil {
			t.Fatal("a decoy was created over another decoy's user")
		}
		remote.mu.Lock()
		defer remote.mu.Unlock()
		if strings.Join(remote.actions, ",") != "GetUser,ListUserTags" {
			t.Fatalf("the refused create sent %q, want only GetUser and ListUserTags", remote.actions)
		}
		if remote.users[colliding] != "owned-decoy-2" || remote.keys["AKIADECOY9999"] != colliding {
			t.Fatalf("the other decoy's user or key changed: users %v keys %v", remote.users, remote.keys)
		}
	})
}

// loggingMongoAdmin records every operation, in order, before the recording
// admin applies it.
type loggingMongoAdmin struct {
	MongoAdmin
	log []string
}

func (m *loggingMongoAdmin) CreateUser(ctx context.Context, db, user string, password []byte, roles []MongoRole) error {
	m.log = append(m.log, "create "+db+"."+user)
	return m.MongoAdmin.CreateUser(ctx, db, user, password, roles)
}

func (m *loggingMongoAdmin) DropUser(ctx context.Context, db, user string) error {
	m.log = append(m.log, "drop "+db+"."+user)
	return m.MongoAdmin.DropUser(ctx, db, user)
}

func (m *loggingMongoAdmin) SetUserPassword(ctx context.Context, db, user string, password []byte) error {
	m.log = append(m.log, "password "+db+"."+user)
	return m.MongoAdmin.SetUserPassword(ctx, db, user, password)
}

// The hosted-key backends share one code path (one vendor stub covers them);
// the reference is "<binding>/<key id>" and the key's name is the principal.
func hostedKeysOwnershipSite() ownershipSite {
	var vendor *fakeVendor
	return ownershipSite{name: "hosted-keys", role: "inference",
		setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			var b *HostedKeyBackend
			b, vendor = fakeHostedBackend(t)
			return b, func() []string {
				var out []string
				for _, binding := range snapshotKeys(vendor.keys) {
					for _, line := range snapshot(vendor.keys[binding]) {
						out = append(out, binding+"/"+line)
					}
				}
				return out
			}
		},
		nameOf: func(ref string) string {
			_, _, raw, err := opaqueBoundRefShapeVersion(ref, "v3")
			if err != nil {
				return ""
			}
			ref = raw
			cut := strings.LastIndex(ref, "/")
			return vendor.keys[ref[:cut]][ref[cut+1:]]
		},
	}
}

// Datadog references are "api_key/<id>"; the key's name is the principal.
func datadogOwnershipSite() ownershipSite {
	fake := &fakeDatadog{keys: map[string]datadogFakeKey{}}
	return ownershipSite{name: "datadog", role: "datadog/ingest",
		setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			server := httptest.NewServer(fake)
			t.Cleanup(server.Close)
			b, err := NewDatadogBackend(DatadogConfig{Endpoint: server.URL, APIKey: []byte("admin-api-key"), ApplicationKey: []byte("admin-app-key"),
				RoleBindings: map[string]string{"datadog/ingest": "api_key"}, UsernamePrefix: "trstctl", AllowInsecureLoopback: true, HTTPClient: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(b.Close)
			return b, func() []string {
				fake.mu.Lock()
				defer fake.mu.Unlock()
				return snapshot(fake.keys)
			}
		},
		nameOf: func(ref string) string {
			fake.mu.Lock()
			defer fake.mu.Unlock()
			return fake.keys[ref[strings.LastIndex(ref, "/")+1:]].name
		},
	}
}

// OpenAI references are "<project>/<service account id>"; the service
// account's name is the principal.
func openAIOwnershipSite() ownershipSite {
	fake := &fakeOpenAI{accounts: map[string]fakeOpenAIAccount{}}
	return ownershipSite{name: "openai", role: "openai/orders",
		setup: func(t *testing.T) (ownershipSiteBackend, func() []string) {
			server := httptest.NewServer(fake)
			t.Cleanup(server.Close)
			b, err := NewOpenAIBackend(OpenAIConfig{Endpoint: server.URL, AdminKey: []byte("sk-admin-fixture"),
				RoleBindings: map[string]string{"openai/orders": "proj_orders"}, UsernamePrefix: "trstctl", AllowInsecureLoopback: true, HTTPClient: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(b.Close)
			return b, func() []string {
				fake.mu.Lock()
				defer fake.mu.Unlock()
				return snapshot(fake.accounts)
			}
		},
		nameOf: func(ref string) string {
			fake.mu.Lock()
			defer fake.mu.Unlock()
			return fake.accounts[ref[strings.LastIndex(ref, "/")+1:]].name
		},
	}
}
