// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/letsencrypt"
	"trstctl.com/trstctl/internal/ca/letsencrypt/acmefake"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// seedRogueCTFindingAt records a CT finding the way the monitor does, at a
// position in a log its CT source watches.
func seedRogueCTFindingAt(t *testing.T, h *servedHarness, info certinfo.Info, logURL string, index int, sourceConfig map[string]any) string {
	t.Helper()
	ctx, now := t.Context(), time.Now().UTC()
	sourceID, runID, findingID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	meta, err := json.Marshal(map[string]any{
		"log_url": logURL, "index": index, "subject": info.Subject, "issuer": info.Issuer,
		"serial": info.SerialNumber, "sans": info.DNSNames, "not_after": info.NotAfter, "matched_domain": "corp.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(sourceConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		if err := h.store.ApplyDiscoverySourceUpsertedTx(ctx, tx, store.DiscoverySource{ID: sourceID, TenantID: h.tenant,
			Kind: "ct_log", Name: "ct-" + sourceID[:8], Config: config, CreatedAt: now, UpdatedAt: now}); err != nil {
			return err
		}
		if err := h.store.ApplyDiscoveryRunQueuedTx(ctx, tx, store.DiscoveryRun{ID: runID, TenantID: h.tenant, SourceID: sourceID, Status: "queued", CreatedAt: now}); err != nil {
			return err
		}
		return h.store.ApplyDiscoveryFindingRecordedTx(ctx, tx, store.DiscoveryFinding{ID: findingID, TenantID: h.tenant, RunID: runID,
			SourceID: sourceID, Kind: "ct_unexpected_issuance", Ref: info.DNSNames[0], Provenance: "ct:" + logURL,
			Fingerprint: info.SHA256Fingerprint, RiskScore: 90, Metadata: meta, DiscoveredAt: now})
	}); err != nil {
		t.Fatalf("seed the CT finding: %v", err)
	}
	return findingID
}

// N10: a certificate another ACME account requested for the tenant's names,
// found in Certificate Transparency, is revoked at the ACME authority through
// trstctl. trstctl reads its bytes back from the log that recorded it, checks
// them against the finding, obtains authorizations for every name with its own
// account, and asks; the authority accepts that under RFC 8555 §7.6.
func TestServedRogueCertificateIsRevokedAtAnACMEAuthorityN10(t *testing.T) {
	fake, err := acmefake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fake.Close)
	fake.EnforceRevocationAuthority()
	ctx := t.Context()
	plugin := func(name string) *letsencrypt.Plugin {
		t.Helper()
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		p, err := letsencrypt.NewPluginWithRemoteAccountSigner(name, fake.DirectoryURL(), http.DefaultClient, key)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Destroy)
		return p
	}
	// Someone else's account requested certificates for the tenant's names.
	other := plugin("someone-else")
	issue := func(names ...string) ([]byte, certinfo.Info) {
		t.Helper()
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: names[0], DNSNames: names}, key)
		if err != nil {
			t.Fatal(err)
		}
		issued, err := other.Issue(ctx, ca.IssueRequest{TenantID: "someone-else", CSR: csr, DNSNames: names, TTL: 24 * time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(issued.CertificatePEM)
		info, err := certinfo.Inspect(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return block.Bytes, info
	}
	rogueDER, rogue := issue("shadow.corp.example", "www.shadow.corp.example")
	secondDER, second := issue("second.corp.example")
	precertDER, precertTBS, err := ctlogtest.IssueCert("pre.corp.example", "pre.corp.example")
	if err != nil {
		t.Fatal(err)
	}
	precert, err := certinfo.Inspect(precertDER)
	if err != nil {
		t.Fatal(err)
	}
	logSrv := ctlogtest.NewServer(ctlogtest.X509Entry(rogueDER), ctlogtest.PrecertEntry(precertDER, precertTBS), ctlogtest.X509Entry(secondDER))
	t.Cleanup(logSrv.Close)
	source := map[string]any{"log": logSrv.URL(), "watched_domains": []string{"corp.example"},
		"allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, logSrv.URL())}}

	h := newServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.ExternalCAs = []ExternalCA{{ID: "corp-acme", Type: "letsencrypt", Name: "Corp ACME", CA: plugin("letsencrypt")}}
	})
	registerServedTenant(t, h, "ACME rogue revocation tenant")
	token := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read", "identities:write")
	const route = "/api/v1/revocation/rogue-certificates/revoke"
	dispatcher := h.srv.obHandler.(*issuanceDispatcher)
	queue := func(findingID, key string) orchestrator.Message {
		t.Helper()
		if status, body := secretsReqKey(t, h, http.MethodPost, route, token, key, map[string]any{
			"discovery_id": findingID, "authority_id": "corp-acme", "reason": "keyCompromise"}); status != http.StatusAccepted {
			t.Fatalf("queue the revocation = %d %s", status, body)
		}
		pending, err := h.srv.outbox.Pending(ctx, h.tenant)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range pending {
			if r.Destination == "revocation.publish" && strings.Contains(string(r.Payload), findingID) {
				return orchestrator.Message{ID: r.ID, TenantID: h.tenant, Destination: r.Destination, Payload: r.Payload, IdempotencyKey: r.IdempotencyKey}
			}
		}
		t.Fatalf("no delivery queued for %s", findingID)
		return orchestrator.Message{}
	}

	// The rogue certificate is revoked by trstctl's account, not its owner's,
	// and a redelivery calls the authority no second time.
	findingID := seedRogueCTFindingAt(t, h, rogue, logSrv.URL(), 0, source)
	message := queue(findingID, "n10-rogue")
	for round := 1; round <= 2; round++ {
		if err := dispatcher.Deliver(ctx, message); err != nil {
			t.Fatalf("delivery round %d: %v", round, err)
		}
	}
	by, owner := fake.RevokedBy(rogue.SerialNumber), fake.OwnerOf(rogue.SerialNumber)
	if by == "" || by == owner || len(fake.Revocations()) != 1 {
		t.Fatalf("revoked by %q (issued by %q) after %d revocation requests; want trstctl's account, once", by, owner, len(fake.Revocations()))
	}
	if got := rogueIssuerRevocationOf(t, h, token, findingID); got == nil || got.Status != "revoked" || got.Reason != "keyCompromise" {
		t.Fatalf("the finding reads %+v; want revoked at the issuer", got)
	}

	// What trstctl cannot prove is the finding's certificate is never sent.
	for name, tc := range map[string]struct {
		info   certinfo.Info
		logURL string
		index  int
		want   string
	}{
		"a precertificate entry":         {precert, logSrv.URL(), 1, "precertificate"},
		"an entry that is another cert":  {rogue, logSrv.URL(), 2, "not the certificate the finding names"},
		"a log its source does not name": {second, "https://ct.example.test/log", 2, "no longer one of its source's logs"},
	} {
		id := seedRogueCTFindingAt(t, h, tc.info, tc.logURL, tc.index, source)
		if err := dispatcher.Deliver(ctx, queue(id, "n10-"+name)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: delivery = %v; want %q", name, err, tc.want)
		}
		if got := rogueIssuerRevocationOf(t, h, token, id); got == nil || got.Status != "queued" {
			t.Fatalf("%s: the finding reads %+v; want still queued", name, got)
		}
	}
	if len(fake.Revocations()) != 1 || fake.RevokedBy(second.SerialNumber) != "" {
		t.Fatalf("the authority saw %d revocation requests; the refused findings must send none", len(fake.Revocations()))
	}

	// N10-L1: a finding at a precertificate entry revokes its issued
	// certificate once another watched log has recorded it under the same
	// issuer and serial; until then nothing is sent.
	thirdDER, third := issue("third.corp.example")
	thirdTBS, err := ctlogtest.TBSOf(thirdDER)
	if err != nil {
		t.Fatal(err)
	}
	precertLog := ctlogtest.NewServer(ctlogtest.PrecertEntry(thirdDER, thirdTBS))
	t.Cleanup(precertLog.Close)
	issuedLog := ctlogtest.NewServer(ctlogtest.X509Entry(secondDER), ctlogtest.X509Entry(thirdDER))
	t.Cleanup(issuedLog.Close)
	sourceFor := func(url string) map[string]any {
		return map[string]any{"log": url, "watched_domains": []string{"corp.example"},
			"allow_private_endpoint": true, "private_egress_cidrs": []string{serviceNowSinkCIDR(t, url)}}
	}
	precertFinding := seedRogueCTFindingAt(t, h, third, precertLog.URL(), 0, sourceFor(precertLog.URL()))
	precertMessage := queue(precertFinding, "n10l1-precert")
	if err := dispatcher.Deliver(ctx, precertMessage); err == nil || !strings.Contains(err.Error(), "no watched log has shown its issued certificate yet") {
		t.Fatalf("a precertificate with no issued certificate seen = %v", err)
	}
	if len(fake.Revocations()) != 1 {
		t.Fatalf("the authority saw %d revocation requests before the issued certificate was seen", len(fake.Revocations()))
	}
	seedRogueCTFindingAt(t, h, third, issuedLog.URL(), 1, sourceFor(issuedLog.URL()))
	if err := dispatcher.Deliver(ctx, precertMessage); err != nil {
		t.Fatalf("the precertificate's revocation once its issued certificate is seen: %v", err)
	}
	if by := fake.RevokedBy(third.SerialNumber); by == "" || by == fake.OwnerOf(third.SerialNumber) || len(fake.Revocations()) != 2 {
		t.Fatalf("the issued certificate was revoked by %q after %d requests; want trstctl's account", by, len(fake.Revocations()))
	}
	if got := rogueIssuerRevocationOf(t, h, token, precertFinding); got == nil || got.Status != "revoked" {
		t.Fatalf("the precertificate's finding reads %+v; want revoked at the issuer", got)
	}
}
