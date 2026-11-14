// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
)

// Q1-L8: a review generated from the access graph carries what each
// dynamic-secret lease holds inside its target, as the leader read it (G2):
// the login, its grants (PostgreSQL's own answer) and when they were read; a
// lease nobody has read yet says so rather than reading as no rights. The
// campaign's coverage statement names those reads and no longer says rights
// inside a target or lease requesters are unseen. Real PostgreSQL.
func TestServedReviewOfReachersCarriesRightsInsideTheTargetQ1L8(t *testing.T) {
	pgDSN, stopPG := startPAMPostgres(t)
	defer stopPG()
	seedPAMPostgresTable(t, pgDSN)
	adminRef := pamPostgresAdminFileRef(t, pgDSN)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.EnableSecretsAPI = true
		resolver := integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}
		pg := config.DynamicSecretProviderConfig{
			TenantID: servedTestTenant, ID: "q1l8-pg", Type: "postgresql",
			AdminDSNRef: adminRef, Database: "postgres", Schema: "public",
			UsernamePrefix: "trstctl", AllowedRoles: []string{"readonly"}, MaxTTL: time.Hour.String(),
		}
		d.TenantDynamicSecretProviders = DynamicSecretProviderRegistry{servedTestTenant: {
			newConfiguredDynamicProvider(pg, map[string]bool{"readonly": true}, time.Hour, resolver, nil),
		}}
		d.DynamicSecretAccessInterval = time.Hour // the test drives each read itself
	})
	startServedExternalCADispatcher(t, h)
	issuer := seedScopedTokenSubject(t, h.store, h.tenant, "q1l8-issuer", "secrets:read", "secrets:write")
	lead := seedScopedTokenSubject(t, h.store, h.tenant, "q1l8-lead", "access:read", "access:write", "graph:read")

	readLease, _ := issueG2Lease(t, h, issuer, "q1l8-read", "q1l8-pg", "readonly")
	if err := h.srv.ResolveDynamicSecretAccessOnce(t.Context()); err != nil {
		t.Fatalf("lease access pass: %v", err)
	}
	unreadLease, _ := issueG2Lease(t, h, issuer, "q1l8-unread", "q1l8-pg", "readonly")
	databaseNode := "res:postgresql_database:postgresql://" + strings.SplitN(strings.SplitN(pgDSN, "@", 2)[1], "?", 2)[0]

	type generated struct {
		Campaign q1Campaign `json:"campaign"`
		Coverage struct {
			Sources    []string `json:"sources"`
			NotCovered []string `json:"not_covered"`
		} `json:"coverage"`
	}
	generate := func(key, target string) generated {
		t.Helper()
		status, raw := secretsReqKey(t, h, http.MethodPost, "/api/v1/access/reviews/generate", lead, key, map[string]any{
			"name": "q1l8 " + key, "source": "graph_reachers", "target": target, "reviewer_subject": "q1l8-reviewer",
		})
		var out generated
		if status != http.StatusCreated || json.Unmarshal(raw, &out) != nil {
			t.Fatalf("generate a review of %s: HTTP %d %s", target, status, raw)
		}
		return out
	}
	refsOf := func(c q1Campaign, lease string) map[string]string {
		t.Helper()
		for _, item := range c.Items {
			if item.NHIID != "lease:"+lease {
				continue
			}
			out := map[string]string{}
			for _, ref := range item.EvidenceRefs {
				for _, prefix := range []string{"graph:rights-login:", "graph:rights-read:", "graph:rights-unknown:", "graph:rights:", "graph:rights-not-read"} {
					if strings.HasPrefix(ref, prefix) {
						out[prefix] = strings.TrimPrefix(ref, prefix)
						break
					}
				}
			}
			return out
		}
		t.Fatalf("no item for lease %s in %+v", lease, c.Items)
		return nil
	}

	// The database's reachers: the read lease with its rights inside it, and
	// the unread one (it reaches the database through its provider).
	db := generate("database", databaseNode)
	if len(db.Campaign.Items) != 2 {
		t.Fatalf("the database's reachers = %+v", db.Campaign.Items)
	}
	rights := refsOf(db.Campaign, readLease)
	if !strings.HasPrefix(rights["graph:rights-login:"], "trstctl_") || rights["graph:rights-read:"] == "" {
		t.Fatalf("the read lease's rights refs = %v", rights)
	}
	if _, err := time.Parse(time.RFC3339, rights["graph:rights-read:"]); err != nil {
		t.Fatalf("rights read at %q: %v", rights["graph:rights-read:"], err)
	}
	for _, grant := range []string{"CONNECT on database postgres", "USAGE on schema public", "SELECT on public.pam_smoke"} {
		if !strings.Contains(rights["graph:rights:"], grant) {
			t.Fatalf("the item's rights %q lack %q", rights["graph:rights:"], grant)
		}
	}
	if strings.Contains(rights["graph:rights:"], "INSERT on") {
		t.Fatalf("a read-only lease's item shows a write: %s", rights["graph:rights:"])
	}

	// The lease nobody has read yet says so, rather than reading as no rights.
	unread := refsOf(db.Campaign, unreadLease)
	if _, ok := unread["graph:rights-not-read"]; !ok || len(unread) != 1 {
		t.Fatalf("the unread lease's rights refs = %v, want only graph:rights-not-read", unread)
	}

	// The coverage statement says what the graph sees now.
	sources := strings.Join(db.Coverage.Sources, "\n")
	notCovered := strings.Join(db.Coverage.NotCovered, "\n")
	if !strings.Contains(sources, "inside PostgreSQL") || !strings.Contains(sources, "who requested each") ||
		strings.Contains(notCovered, "what a role can do once connected") || strings.Contains(notCovered, "leases do not record their holder") {
		t.Fatalf("coverage = %+v", db.Coverage)
	}
	t.Logf("Q1L8_RIGHTS_OK grants=%q", rights["graph:rights:"])
}
