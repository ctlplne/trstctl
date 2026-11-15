// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/graph"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// q1l9DecoyKinds is every decoy kind the census plants. A kind the honey
// token table admits that is not listed here fails the census, so a new decoy
// kind gets its graph case before it ships.
var q1l9DecoyKinds = []string{"native", "aws", "secret", "database", "file", "kubernetes"}

// TestServedGraphCensusRevealsNoDecoyOfAnyKindQ1L9 is Q1-L9's Done-when
// (served): the access graph must never tell its reader which credentials are
// bait. One decoy of every kind the honey token table admits is planted
// through its own registration (a native honeytoken, an AWS key on its decoy
// lease, a decoy secret, a database decoy login on its decoy lease, a decoy
// file and a Kubernetes decoy token), beside ordinary credentials of the same
// shapes. The graph is then built from every input it reads, through the
// served route for a reader holding graph:read, access:read and secrets:read
// and directly with every option: no node or edge names a decoy's ID, label,
// placement, lease, key, file or token, nor the words decoy, honey or bait;
// the decoy secret reads as an ordinary secret, with the same attributes as
// its neighbor; and the ordinary lease is listed, so the census is not empty.
func TestServedGraphCensusRevealsNoDecoyOfAnyKindQ1L9(t *testing.T) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.EnableSecretsAPI = true })
	// Its own tenant: the decoys and secrets it plants stay out of the shared
	// served tenant's other tests.
	const tenant = "a1190009-19a9-4a19-8a19-0000a1190009"
	registerServedTenantID(t, h, tenant, "Q1-L9 decoy census tenant")
	ctx := events.ContextWithActor(context.Background(), events.Actor{Subject: "q1l9-planter"})
	planter := seedScopedTokenSubject(t, h.store, tenant, "q1l9-planter", "secrets:read", "secrets:write")
	reader := seedScopedTokenSubject(t, h.store, tenant, "q1l9-graph-reader", "graph:read", "access:read", "secrets:read")

	// Every kind the table admits has a case here.
	var check string
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname = 'honey_tokens_kind_check'`).Scan(&check); err != nil {
		t.Fatal(err)
	}
	var admitted []string
	for _, m := range regexp.MustCompile(`'([a-z_]+)'`).FindAllStringSubmatch(check, -1) {
		admitted = append(admitted, m[1])
	}
	if len(admitted) == 0 {
		t.Fatalf("read no decoy kinds from %q", check)
	}
	for _, kind := range admitted {
		if !slices.Contains(q1l9DecoyKinds, kind) {
			t.Fatalf("decoy kind %q has no graph census case: plant one here and prove the graph does not reveal it", kind)
		}
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	lease := func(id, provider, role string) {
		t.Helper()
		pending := projections.DynamicSecretLeasePending{
			ID: id, IdempotencyKey: "issue-" + id, RequestBinding: "sha256:issue-" + id,
			Provider: provider, Role: role, ExpiresAt: now.Add(time.Hour), HardExpiresAt: now.Add(2 * time.Hour),
		}
		data, err := json.Marshal(pending)
		if err != nil {
			t.Fatal(err)
		}
		event, err := h.log.Append(ctx, events.Event{Type: projections.EventDynamicSecretLeasePending, TenantID: tenant, Time: now, Data: data})
		if err != nil {
			t.Fatal(err)
		}
		if err := projections.New(h.store).Apply(ctx, event); err != nil {
			t.Fatal(err)
		}
		record, err := h.store.GetDynamicSecretLease(ctx, tenant, id)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.store.WithTenant(ctx, tenant, func(tx pgx.Tx) error {
			return h.store.ApplyDynamicSecretLeaseIssuedTx(ctx, tx, store.DynamicSecretLease{
				ID: record.ID, TenantID: tenant, TenantEpoch: record.TenantEpoch,
				IdempotencyKey: record.IdempotencyKey, RequestBinding: record.RequestBinding,
				Provider: provider, Role: role, BackendRef: "q1l9-login-" + id,
				SealedCredential: []byte("sealed"), IssuedAt: now, ExpiresAt: record.ExpiresAt, HardExpiresAt: record.HardExpiresAt, UpdatedAt: now,
			})
		}); err != nil {
			t.Fatal(err)
		}
	}
	secret := func(name, key string) {
		t.Helper()
		if status, out := secretsReqKey(t, h, http.MethodPost, "/api/v1/secrets/store", planter, key, map[string]any{"name": name, "value": "q1l9-value-" + key}); status != http.StatusCreated {
			t.Fatalf("create %s: HTTP %d %s", name, status, out)
		}
	}

	// markers name what would give each decoy away.
	markers := []string{}
	planted := map[string]string{}
	native, _, err := h.srv.orch.CreateHoneyToken(ctx, tenant, "q1l9-label-native", "q1l9-placement-native")
	if err != nil {
		t.Fatal(err)
	}
	planted["native"] = native.ID
	markers = append(markers, native.ID, "q1l9-label-native", "q1l9-placement-native")

	lease("q1l9-lease-aws", "honey.aws.q1l9-account", "decoy")
	aws, err := h.srv.orch.CreateAWSHoneyToken(ctx, tenant, projections.AWSHoneyTokenCreated{
		Name: "q1l9-label-aws", Placement: "q1l9-placement-aws", AccountConfigID: "q1l9-account", AccountID: "111122223333",
		AccessKeyID: "q1l9-access-key-id", LeaseID: "q1l9-lease-aws", Regions: []string{"us-east-1"}, PollIntervalSeconds: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	planted["aws"] = aws.ID
	markers = append(markers, aws.ID, "q1l9-label-aws", "q1l9-placement-aws", "q1l9-lease-aws", "q1l9-access-key-id")

	secret("q1l9/ops/admin-password", "q1l9-kb")
	secret("q1l9/ops/api-key", "q1l9-kr")
	decoySecret, err := h.srv.orch.RegisterDecoySecret(ctx, tenant, "q1l9-label-sec", "q1l9-place-sec", "q1l9/ops/admin-password")
	if err != nil {
		t.Fatal(err)
	}
	planted["secret"] = decoySecret.ID
	markers = append(markers, decoySecret.ID, "q1l9-label-sec", "q1l9-place-sec")

	lease("q1l9-lease-db", "q1l9-pg", "decoy")
	lease("q1l9-lease-real", "q1l9-pg", "reader")
	database, err := h.srv.orch.RegisterDatabaseDecoy(ctx, tenant, "q1l9-label-database", "q1l9-placement-database", "q1l9-pg", "q1l9-lease-db", "decoy")
	if err != nil {
		t.Fatal(err)
	}
	planted["database"] = database.ID
	markers = append(markers, database.ID, "q1l9-label-database", "q1l9-placement-database", "q1l9-lease-db")

	file, _, err := h.srv.orch.RegisterDecoyFile(ctx, tenant, "build-07.q1l9.test", "/home/ci/.config/q1l9-credentials", "SHA256:q1l9-file-fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	planted["file"] = file.ID
	markers = append(markers, file.ID, "/home/ci/.config/q1l9-credentials", "q1l9-file-fingerprint")

	kube, err := h.srv.orch.RegisterKubernetesDecoy(ctx, tenant, "q1l9-label-kubernetes", "q1l9-placement-kubernetes", "q1l9-cluster", "payments", "q1l9-reporting", "q1l9-reporting-token")
	if err != nil {
		t.Fatal(err)
	}
	planted["kubernetes"] = kube.ID
	markers = append(markers, kube.ID, "q1l9-label-kubernetes", "q1l9-placement-kubernetes", "q1l9-reporting-token")

	for _, kind := range q1l9DecoyKinds {
		var got string
		if err := h.store.SystemPool().QueryRow(ctx, `SELECT kind FROM honey_tokens WHERE tenant_id = $1 AND id = $2`, tenant, planted[kind]).Scan(&got); err != nil || got != kind {
			t.Fatalf("the %s decoy is recorded as %q (%v)", kind, got, err)
		}
	}

	checkCensus := func(where string, nodes []graph.Node, edges []graph.Edge) {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"nodes": nodes, "edges": edges})
		if err != nil {
			t.Fatal(err)
		}
		text := strings.ToLower(string(raw))
		for _, marker := range append(markers, "decoy", "honey", "bait") {
			if strings.Contains(text, strings.ToLower(marker)) {
				t.Fatalf("%s reveals a decoy: it names %q", where, marker)
			}
		}
		var leaseListed bool
		attrs := map[string][]string{}
		for _, n := range nodes {
			if strings.Contains(mustJSON(t, n), "q1l9-lease-real") {
				leaseListed = true
			}
			if n.Name == "q1l9/ops/admin-password" || n.Name == "q1l9/ops/api-key" {
				keys := make([]string, 0, len(n.Attrs))
				for k := range n.Attrs {
					keys = append(keys, k)
				}
				slices.Sort(keys)
				attrs[n.Name] = keys
			}
		}
		if !leaseListed {
			t.Fatalf("%s lists no ordinary lease: the census would pass on an empty graph", where)
		}
		if len(attrs) != 2 {
			t.Fatalf("%s lists %d of the decoy secret and its neighbor, want both, as any secrets:read reader sees them", where, len(attrs))
		}
		if !slices.Equal(attrs["q1l9/ops/admin-password"], attrs["q1l9/ops/api-key"]) {
			t.Fatalf("%s tells the decoy secret from its neighbor: %v vs %v", where, attrs["q1l9/ops/admin-password"], attrs["q1l9/ops/api-key"])
		}
	}

	// The served graph, for a reader who sees every input.
	status, raw := secretsReq(t, h, http.MethodGet, "/api/v1/graph", reader, nil)
	if status != http.StatusOK {
		t.Fatalf("graph: HTTP %d %s", status, raw)
	}
	var served struct {
		Nodes []graph.Node `json:"nodes"`
		Edges []graph.Edge `json:"edges"`
	}
	if err := json.Unmarshal(raw, &served); err != nil {
		t.Fatalf("graph: %v %s", err, raw)
	}
	checkCensus("the served graph", served.Nodes, served.Edges)

	// The graph built with every option.
	built, err := graph.BuildWith(ctx, h.store, tenant, graph.BuildOptions{IncludeSecrets: true})
	if err != nil {
		t.Fatal(err)
	}
	checkCensus("the graph built from every input", built.Nodes(), built.Edges())
	t.Logf("Q1L9_OK kinds=%v", admitted)
}
