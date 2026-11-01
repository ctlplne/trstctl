// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/store"
)

// g2AWSStandIn answers STS AssumeRole and the two IAM reads the access worker
// makes, checking that each is signed for its own service and region.
type g2AWSStandIn struct {
	*httptest.Server
	denyIAM  atomic.Bool
	mu       sync.Mutex
	iamCalls int
	sessions int
}

const g2RoleARN = "arn:aws:iam::123456789012:role/delivery/g2-deployer"

func newG2AWSStandIn(t *testing.T) *g2AWSStandIn {
	t.Helper()
	s := &g2AWSStandIn{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		auth := r.Header.Get("Authorization")
		switch action := r.Form.Get("Action"); action {
		case "AssumeRole":
			seconds, err := strconv.Atoi(r.Form.Get("DurationSeconds"))
			if err != nil || !strings.Contains(auth, "/us-west-2/sts/aws4_request") || r.Form.Get("RoleArn") != g2RoleARN {
				http.Error(w, "not a signed AssumeRole for the bound role", http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			s.sessions++
			n := s.sessions
			s.mu.Unlock()
			expires := time.Now().UTC().Add(time.Duration(seconds)*time.Second + time.Minute).Format(time.RFC3339)
			_, _ = fmt.Fprintf(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIAG2SESSION%04d</AccessKeyId><SecretAccessKey>g2-session-secret-%d</SecretAccessKey><SessionToken>g2-session-token-%d</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>AROAG2DEPLOYER:%s</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`,
				n, n, n, expires, r.Form.Get("RoleSessionName"))
		case "ListAttachedRolePolicies", "ListRolePolicies":
			s.mu.Lock()
			s.iamCalls++
			s.mu.Unlock()
			switch {
			case !strings.Contains(auth, "/us-east-1/iam/aws4_request"):
				http.Error(w, "not signed for IAM", http.StatusBadRequest)
			case s.denyIAM.Load():
				w.WriteHeader(http.StatusForbidden)
				_, _ = fmt.Fprint(w, `<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>`)
			case r.Form.Get("RoleName") != "g2-deployer":
				w.WriteHeader(http.StatusNotFound)
				_, _ = fmt.Fprint(w, `<ErrorResponse><Error><Code>NoSuchEntity</Code></Error></ErrorResponse>`)
			case action == "ListAttachedRolePolicies":
				_, _ = fmt.Fprint(w, `<ListAttachedRolePoliciesResponse><ListAttachedRolePoliciesResult><AttachedPolicies><member><PolicyName>g2-artifact-publish</PolicyName><PolicyArn>arn:aws:iam::123456789012:policy/g2-artifact-publish</PolicyArn></member></AttachedPolicies><IsTruncated>false</IsTruncated></ListAttachedRolePoliciesResult></ListAttachedRolePoliciesResponse>`)
			default:
				_, _ = fmt.Fprint(w, `<ListRolePoliciesResponse><ListRolePoliciesResult><PolicyNames><member>g2-kms-decrypt</member></PolicyNames><IsTruncated>false</IsTruncated></ListRolePoliciesResult></ListRolePoliciesResponse>`)
			}
		default:
			http.Error(w, "unexpected action", http.StatusBadRequest)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *g2AWSStandIn) iamReads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.iamCalls
}

type g2GraphNode struct {
	ID    string            `json:"id"`
	Kind  string            `json:"kind"`
	Name  string            `json:"name"`
	Attrs map[string]string `json:"attrs"`
}

type g2Graph struct {
	Nodes []g2GraphNode `json:"nodes"`
	Edges []struct {
		From   string `json:"from"`
		To     string `json:"to"`
		Type   string `json:"type"`
		Source string `json:"source"`
	} `json:"edges"`
}

func (g g2Graph) node(id string) (g2GraphNode, bool) {
	for _, n := range g.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return g2GraphNode{}, false
}

func (g g2Graph) edge(from, to, typ string) bool {
	for _, e := range g.Edges {
		if e.From == from && e.To == to && e.Type == typ {
			return true
		}
	}
	return false
}

func readG2Graph(t *testing.T, h *servedHarness, token string) g2Graph {
	t.Helper()
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/graph", token, nil)
	if status != http.StatusOK {
		t.Fatalf("graph: HTTP %d %s", status, body)
	}
	var g g2Graph
	if err := json.Unmarshal(body, &g); err != nil {
		t.Fatalf("decode graph: %v", err)
	}
	return g
}

func issueG2Lease(t *testing.T, h *servedHarness, token, key, provider, role string) (string, string) {
	t.Helper()
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/leases", token, key,
		map[string]any{"provider": provider, "role": role, "ttl_seconds": 900})
	if status != http.StatusCreated {
		t.Fatalf("issue %s lease: HTTP %d %s", provider, status, body)
	}
	var lease struct {
		ID         string `json:"id"`
		Credential string `json:"credential"`
	}
	if err := json.Unmarshal(body, &lease); err != nil || lease.ID == "" || lease.Credential == "" {
		t.Fatalf("issue %s lease: no lease or credential (%v)", provider, err)
	}
	return lease.ID, lease.Credential
}

// G2: a lease reaches what its login can reach, read from the target itself. A
// PostgreSQL lease links to the database with its login role and the grants
// PostgreSQL reports for that role; an AWS STS lease links to the IAM role it
// assumed with the role's attached and inline policies, read from IAM. A target
// that cannot be read shows the grants as unknown with a reason — never as none
// — and is read again later.
func TestServedLeaseAccessShowsTheDatabaseAndTheRoleG2(t *testing.T) {
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminRef := pamPostgresAdminFileRef(t, pgDSN)
	aws := newG2AWSStandIn(t)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		resolver := integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}
		pg := config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "warehouse-pg", Type: "postgresql",
			AdminDSNRef: adminRef, Database: "postgres", Schema: "public",
			UsernamePrefix: "trstctl", AllowedRoles: []string{"readonly"}, MaxTTL: time.Hour.String(),
		}
		sts := config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "aws-deploy", Type: "aws-sts", Endpoint: aws.URL, IAMEndpoint: aws.URL,
			AllowInsecureLoopback: true, Region: "us-west-2", AccessKeyID: "AKIAG2ADMIN",
			SecretAccessRef: writeServedCredentialFile(t, "g2-aws-secret", "g2-admin-secret"),
			AllowedRoles:    []string{"deployer"}, RoleBindings: map[string]string{"deployer": g2RoleARN}, MaxTTL: "1h",
		}
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {
			newConfiguredDynamicProvider(pg, map[string]bool{"readonly": true}, time.Hour, resolver, nil),
			newConfiguredDynamicProvider(sts, map[string]bool{"deployer": true}, time.Hour, resolver, nil),
		}}
		d.DynamicSecretAccessInterval = time.Hour // the test drives each read itself
	})
	startServedExternalCADispatcher(t, h)
	ctx := t.Context()
	issuer := seedScopedTokenSubject(t, h.store, h.tenant, "g2-issuer", "secrets:read", "secrets:write")
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "g2-graph-reader", "graph:read")
	resolve := func() {
		t.Helper()
		if err := h.srv.ResolveDynamicSecretAccessOnce(ctx); err != nil {
			t.Fatalf("lease access pass: %v", err)
		}
	}

	pgLease, pgCredential := issueG2Lease(t, h, issuer, "g2-pg-1", "warehouse-pg", "readonly")
	stsLease, stsCredential := issueG2Lease(t, h, issuer, "g2-sts-1", "aws-deploy", "deployer")
	parsed, err := url.Parse(pgCredential)
	if err != nil {
		t.Fatal("the PostgreSQL lease credential is not a DSN")
	}
	pgPassword, _ := parsed.User.Password()
	var session struct {
		SecretAccessKey string `json:"secret_access_key"`
	}
	if err := json.Unmarshal([]byte(stsCredential), &session); err != nil || pgPassword == "" || session.SecretAccessKey == "" {
		t.Fatalf("lease credentials lack their secrets (%v)", err)
	}
	g := readG2Graph(t, h, reader)
	if n, ok := g.node("lease:" + pgLease); !ok || n.Attrs["access_status"] != "not_read" || n.Attrs["grants"] != "" {
		t.Fatalf("a lease nobody has read yet = %+v", n)
	}

	resolve()
	// The database node names host, port and database, never the admin login.
	databaseNode := "res:postgresql_database:postgresql://" + strings.SplitN(strings.SplitN(pgDSN, "@", 2)[1], "?", 2)[0]
	roleNode := "res:aws_iam_role:" + g2RoleARN
	g = readG2Graph(t, h, reader)
	pg, ok := g.node("lease:" + pgLease)
	if !ok || pg.Attrs["access_status"] != store.DynamicSecretAccessResolved || !strings.HasPrefix(pg.Attrs["login"], "trstctl_") {
		t.Fatalf("PostgreSQL lease node = %+v", pg)
	}
	for _, grant := range []string{"CONNECT on database postgres", "USAGE on schema public", "SELECT on public.pam_smoke"} {
		if !strings.Contains(pg.Attrs["grants"], grant) {
			t.Fatalf("PostgreSQL lease grants %q lack %q", pg.Attrs["grants"], grant)
		}
	}
	for _, write := range []string{"INSERT on public.pam_smoke", "UPDATE on", "DELETE on"} {
		if strings.Contains(pg.Attrs["grants"], write) {
			t.Fatalf("a read-only lease shows %q: %s", write, pg.Attrs["grants"])
		}
	}
	db, ok := g.node(databaseNode)
	if !ok || db.Kind != "resource" || db.Attrs["resource_kind"] != "database" ||
		!g.edge("lease:"+pgLease, databaseNode, "GRANTS_ACCESS") || !g.edge("res:dynamic-secret:warehouse-pg", databaseNode, "CONNECTS_TO") {
		t.Fatalf("no grants-access link from the PostgreSQL lease to %s: node %+v", databaseNode, db)
	}
	// The grants are PostgreSQL's own answer for that login.
	conn, err := pgx.Connect(ctx, pgDSN)
	if err != nil {
		t.Fatal(err)
	}
	var canSelect, canInsert bool
	if err := conn.QueryRow(ctx, `SELECT has_table_privilege($1, 'public.pam_smoke', 'SELECT'), has_table_privilege($1, 'public.pam_smoke', 'INSERT')`,
		pg.Attrs["login"]).Scan(&canSelect, &canInsert); err != nil || !canSelect || canInsert {
		t.Fatalf("PostgreSQL says SELECT=%t INSERT=%t for %s (%v)", canSelect, canInsert, pg.Attrs["login"], err)
	}
	_ = conn.Close(ctx)

	st, ok := g.node("lease:" + stsLease)
	if !ok || st.Attrs["access_status"] != store.DynamicSecretAccessResolved || !strings.HasPrefix(st.Attrs["login"], "AROAG2DEPLOYER:") ||
		st.Attrs["target"] != g2RoleARN || st.Attrs["grant_count"] != "2" ||
		!strings.Contains(st.Attrs["grants"], "managed policy g2-artifact-publish (arn:aws:iam::123456789012:policy/g2-artifact-publish)") ||
		!strings.Contains(st.Attrs["grants"], "inline policy g2-kms-decrypt") {
		t.Fatalf("STS lease node = %+v", st)
	}
	if role, ok := g.node(roleNode); !ok || role.Attrs["resource_kind"] != "aws_iam_role" || !g.edge("lease:"+stsLease, roleNode, "GRANTS_ACCESS") {
		t.Fatalf("no grants-access link from the STS lease to the role: %+v", role)
	}

	// A fresh observation is not read again.
	reads := aws.iamReads()
	resolve()
	if aws.iamReads() != reads {
		t.Fatalf("a fresh lease was read again: %d IAM reads, then %d", reads, aws.iamReads())
	}
	if due, err := h.store.DynamicSecretLeasesNeedingAccess(ctx, h.tenant, time.Now(), 6*time.Hour, 5*time.Minute, 50); err != nil || len(due) != 0 {
		t.Fatalf("leases still due after a pass: %d (%v)", len(due), err)
	}

	// IAM refuses the provider's credentials and the database goes away: both
	// new leases read unknown, with the reason, and still name their target.
	aws.denyIAM.Store(true)
	deniedLease, _ := issueG2Lease(t, h, issuer, "g2-sts-2", "aws-deploy", "deployer")
	downLease, _ := issueG2Lease(t, h, issuer, "g2-pg-2", "warehouse-pg", "readonly")
	stopPG()
	resolve()
	g = readG2Graph(t, h, reader)
	for lease, want := range map[string][2]string{deniedLease: {"access_denied", roleNode}, downLease: {"target_unreachable", databaseNode}} {
		n, _ := g.node("lease:" + lease)
		if n.Attrs["access_status"] != store.DynamicSecretAccessUnknown || n.Attrs["grants"] != "unknown" ||
			n.Attrs["access_reason"] != want[0] || !g.edge("lease:"+lease, want[1], "GRANTS_ACCESS") {
			t.Fatalf("an unreadable target reads as %+v, want unknown (%s) linked to %s", n.Attrs, want[0], want[1])
		}
	}
	if n, _ := g.node("lease:" + pgLease); n.Attrs["access_status"] != store.DynamicSecretAccessResolved {
		t.Fatalf("an earlier observation was lost: %+v", n.Attrs)
	}

	// Unknown is read again once its retry is due, and resolves.
	aws.denyIAM.Store(false)
	if _, err := h.store.SystemPool().Exec(ctx,
		`UPDATE dynamic_secret_lease_access SET checked_at = checked_at - interval '6 minutes' WHERE tenant_id = $1 AND lease_id = $2`,
		h.tenant, deniedLease); err != nil {
		t.Fatal(err)
	}
	resolve()
	g = readG2Graph(t, h, reader)
	if n, _ := g.node("lease:" + deniedLease); n.Attrs["access_status"] != store.DynamicSecretAccessResolved || n.Attrs["grant_count"] != "2" {
		t.Fatalf("the retried lease = %+v", n.Attrs)
	}

	for _, leaked := range []string{"g2-admin-secret", session.SecretAccessKey, pgPassword} {
		if h.logContains(t, leaked) {
			t.Fatal("a credential reached the event log")
		}
	}
	t.Logf("G2_OK pg=%s grants=%q sts=%s policies=%q", pgLease, pg.Attrs["grants"], stsLease, st.Attrs["grants"])
}

// G2 against a stock IAM API: LocalStack's IAM lists the role's attached
// managed policy and inline policy, and an STS lease issued through trstctl
// shows both. LocalStack does not enforce IAM, so this proves the wire shapes,
// not AWS authorization.
func TestServedLeaseAccessReadsLocalStackIAMG2(t *testing.T) {
	if testing.Short() {
		t.Skip("container acceptance test")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	if out, err := exec.Command("docker", "image", "inspect", a202LocalStackImage).CombinedOutput(); err != nil { // #nosec G204 -- test executes a fixed local tool or fixture it built itself (CWE-78)
		t.Skipf("the pinned LocalStack image is not present locally: %v\n%s", err, out)
	}
	localstack, address := a201Container(t, "4566", "-e", "SERVICES=iam,sts", a202LocalStackImage)
	endpoint := "http://" + address
	a201Await(t, "LocalStack IAM and STS", func() bool {
		resp, err := http.Get(endpoint + "/_localstack/health")
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		var health struct{ Services map[string]string }
		return json.NewDecoder(resp.Body).Decode(&health) == nil &&
			(health.Services["iam"] == "available" || health.Services["iam"] == "running") &&
			(health.Services["sts"] == "available" || health.Services["sts"] == "running")
	})
	trust := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sts:AssumeRole"}]}`
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::g2-artifacts/*"}]}`
	for _, args := range [][]string{
		{"iam", "create-role", "--role-name", "g2-publisher", "--assume-role-policy-document", trust},
		{"iam", "create-policy", "--policy-name", "g2-artifact-publish", "--policy-document", policy},
		{"iam", "attach-role-policy", "--role-name", "g2-publisher", "--policy-arn", "arn:aws:iam::000000000000:policy/g2-artifact-publish"},
		{"iam", "put-role-policy", "--role-name", "g2-publisher", "--policy-name", "g2-inline-kms", "--policy-document", policy},
	} {
		if out, err := a201Exec(localstack, append([]string{"awslocal"}, args...)...); err != nil {
			t.Fatalf("awslocal %v: %v %s", args, err, out)
		}
	}
	roleARN := "arn:aws:iam::000000000000:role/g2-publisher"
	registry, err := dynamicSecretProvidersFromConfig(context.Background(), []config.DynamicSecretProviderConfig{{
		TenantID: servedTestTenant, ID: "aws-publish", Type: "aws-sts", Endpoint: endpoint, IAMEndpoint: endpoint,
		AllowInsecureLoopback: true, Region: "us-east-1", AccessKeyID: "test",
		SecretAccessRef: writeServedCredentialFile(t, "aws-secret", "test"),
		AllowedRoles:    []string{"publisher"}, RoleBindings: map[string]string{"publisher": roleARN}, MaxTTL: "1h",
	}}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		d.TenantDynamicSecretProviders = registry
		d.DynamicSecretAccessInterval = time.Hour
	})
	startServedExternalCADispatcher(t, h)
	issuer := seedScopedTokenSubject(t, h.store, h.tenant, "g2-issuer", "secrets:read", "secrets:write")
	reader := seedScopedTokenSubject(t, h.store, h.tenant, "g2-graph-reader", "graph:read")
	lease, _ := issueG2Lease(t, h, issuer, "g2-localstack", "aws-publish", "publisher")
	if err := h.srv.ResolveDynamicSecretAccessOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	g := readG2Graph(t, h, reader)
	n, _ := g.node("lease:" + lease)
	if n.Attrs["access_status"] != store.DynamicSecretAccessResolved || n.Attrs["target"] != roleARN ||
		!strings.Contains(n.Attrs["grants"], "managed policy g2-artifact-publish (arn:aws:iam::000000000000:policy/g2-artifact-publish)") ||
		!strings.Contains(n.Attrs["grants"], "inline policy g2-inline-kms") || !g.edge("lease:"+lease, "res:aws_iam_role:"+roleARN, "GRANTS_ACCESS") {
		t.Fatalf("LocalStack STS lease = %+v", n.Attrs)
	}
	t.Logf("G2_LOCALSTACK_OK lease=%s login=%s grants=%q", lease, n.Attrs["login"], n.Attrs["grants"])
}
