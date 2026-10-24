// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/revocationhealth"
)

// A107: the revocation scheduler sends an AD CS LDAP distribution point to
// the AD CS discovery binding whose configuration DN covers it, pinned to
// that source's relay, and the relay redeems the bind credential once for the
// attempt. An LDAP distribution point no source covers is still probed in the
// ordinary batch (where the relay reports that it needs a binding), and that
// batch has nothing to redeem.
func TestServedLDAPDistributionPointsAreProbedThroughTheADCSBinding(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, relay.KindRevocationProbe)
	if _, err := h.client.Heartbeat(ctx, &transport.HeartbeatRequest{AgentID: h.agent, Version: "a107-test", Status: "active"}); err != nil {
		t.Fatalf("relay heartbeat: %v", err)
	}
	relayID := agentRowID(h.tenant, h.agent)
	const (
		secretName = "adcs/crl-reader"          // #nosec G101 -- a logical fixture name, not secret material (CWE-798).
		secretRef  = "secret://adcs/crl-reader" // #nosec G101 -- a non-secret reference, not secret material (CWE-798).
		secretBody = "a107-directory-bind-canary"
		corpConfig = "CN=Configuration,DC=corp,DC=example"
	)
	sealed, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, secretName, []byte(secretBody))
	if err != nil {
		t.Fatal(err)
	}
	seedApplicationSecretFixture(t, h.store, h.tenant, secretName, sealed)
	token := seedScopedToken(t, h.store, h.tenant, "discovery:read", "discovery:write")
	status, body := secretsReqKey(t, h.servedHarness, http.MethodPost, "/api/v1/discovery/sources", token, "a107-source", map[string]any{
		"name": "corp-adcs", "kind": "adcs",
		"config": map[string]any{"url": "ldaps://dc01.corp.example:636", "configuration_dn": corpConfig,
			"bind_dn": "CN=crl-reader,OU=Service Accounts,DC=corp,DC=example", "password_ref": secretRef, "relay_agent_id": relayID},
	})
	var source struct {
		ID string `json:"id"`
	}
	if status != http.StatusCreated || json.Unmarshal(body, &source) != nil {
		t.Fatalf("AD CS source = %d %s", status, body)
	}

	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "Corp Issuing CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caInfo, err := certinfo.Inspect(caDER)
	if err != nil {
		t.Fatal(err)
	}
	recordInventoryCertificateAUD38(t, h, caDER, caInfo)
	corpCDP := "ldap:///CN=Corp%20Issuing%20CA,CN=dc01,CN=CDP,CN=Public%20Key%20Services,CN=Services," + corpConfig +
		"?certificateRevocationList?base?objectClass=cRLDistributionPoint"
	otherCDP := "ldap:///CN=Other%20CA,CN=CDP,CN=Configuration,DC=other,DC=example?certificateRevocationList?base"
	for i, cdp := range []string{corpCDP, otherCDP} {
		leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(leafKey.Destroy)
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: []string{"web.corp.example", "web.other.example"}[i]}, leafKey)
		if err != nil {
			t.Fatal(err)
		}
		leafDER, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csr, time.Hour, crypto.LeafProfile{CRLDistributionPoints: []string{cdp}})
		if err != nil {
			t.Fatal(err)
		}
		leafInfo, err := certinfo.Inspect(leafDER)
		if err != nil {
			t.Fatal(err)
		}
		recordInventoryCertificateAUD38(t, h, leafDER, leafInfo)
	}

	if n, err := h.srv.RunRevocationHealthOnce(ctx); err != nil || n != 2 {
		t.Fatalf("scheduler queued %d endpoints (%v), want both LDAP distribution points", n, err)
	}
	type row struct {
		payload []byte
		agentID string
	}
	var rows []row
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		r, err := tx.Query(ctx, `SELECT payload, COALESCE(required_agent_id::text, '') FROM outbox WHERE tenant_id=$1 AND destination=$2 ORDER BY id`,
			h.tenant, relay.KindRevocationProbe)
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var x row
			if err := r.Scan(&x.payload, &x.agentID); err != nil {
				return err
			}
			rows = append(rows, x)
		}
		return r.Err()
	}); err != nil {
		t.Fatal(err)
	}
	var bound, plain *revocationhealth.Intent
	for _, x := range rows {
		var intent revocationhealth.Intent
		if err := json.Unmarshal(x.payload, &intent); err != nil {
			t.Fatal(err)
		}
		if intent.LDAPBinding != nil {
			if x.agentID != relayID {
				t.Fatalf("bound batch pinned to %q, want the AD CS source's relay %q", x.agentID, relayID)
			}
			bound = &intent
		} else {
			plain = &intent
		}
	}
	if bound == nil || plain == nil || len(bound.Targets) != 1 || bound.Targets[0].Endpoint != corpCDP ||
		bound.LDAPBinding.SourceID != source.ID || bound.LDAPBinding.PasswordRef != secretRef || bound.LDAPBinding.URL != "ldaps://dc01.corp.example:636" ||
		len(plain.Targets) != 1 || plain.Targets[0].Endpoint != otherCDP {
		t.Fatalf("revocation batches: bound=%+v plain=%+v", bound, plain)
	}

	claim := func() transport.ClaimedJob {
		t.Helper()
		claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{Kinds: []string{relay.KindRevocationProbe}, Limit: 1})
		if err != nil || len(claimed.Jobs) != 1 {
			t.Fatalf("relay claim: %+v %v", claimed, err)
		}
		return claimed.Jobs[0]
	}
	for range 2 {
		job := claim()
		var intent revocationhealth.Intent
		if err := json.Unmarshal(job.Payload, &intent); err != nil {
			t.Fatal(err)
		}
		redeemed, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt})
		if intent.LDAPBinding == nil {
			if err == nil {
				t.Fatalf("the plain batch redeemed %+v; it names no credential", redeemed)
			}
			continue
		}
		if err != nil || len(redeemed.Items) != 1 || redeemed.Items[0].Name != secretRef || !bytes.Equal(redeemed.Items[0].Value, []byte(secretBody)) {
			t.Fatalf("bound batch redemption = %+v err=%v", redeemed, err)
		}
		if _, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{JobID: job.JobID, Attempt: job.Attempt}); err == nil {
			t.Fatal("bind credential redeemed twice for one claim")
		}
	}
}
