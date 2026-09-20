// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"net"
	"trstctl.com/trstctl/internal/agent/transport"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Host-generated renewal against the running server (epic B2).
//
// The unit tests prove the authorization rule is correct in isolation. These
// prove it is REACHED: the RPC is registered on the served descriptor, it runs
// inside the agent bulkhead, and an agent holding a real lease against a real
// database gets a real refusal or a real certificate.
//
// The last test is the one the epic is actually judged on. It performs a whole
// renewal and then sweeps the control plane's own tables for private key
// material, because "the key never came here" is the claim, and the only way to
// check a claim about absence is to go and look.

// seedRenewalJob queues an endpoint.renew job bound to the given names.
func seedRenewalJob(t *testing.T, ctx context.Context, h *roleHarness, idemKey string, names []string, verifyAddress ...string) {
	t.Helper()
	// A real identity, because the CSR is issued AGAINST one: the certificate
	// this produces is recorded on the identity's own history, which is what
	// makes the custody column mean something to an operator reading it later.
	owner, err := h.srv.orch.CreateOwner(ctx, h.tenant, string(store.OwnerTeam), "Platform Team", "platform@example.test")
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	identity, err := h.srv.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: names[0], OwnerID: owner.ID,
	})
	if err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	// This source fixture targets job authorization and signed custody. The
	// identity stays requested; the test-only queue seed below does not prove
	// deployment or the end-to-end lifecycle scheduler's job creation.
	intent := RelayDeployIntent{
		Connector:         "nginx",
		Target:            "edge-1",
		IdentityID:        identity.ID,
		SubjectCommonName: names[0],
		SubjectDNSNames:   names,
	}
	if len(verifyAddress) != 0 {
		intent.TargetID = identity.ID
		intent.VerifyAddress = verifyAddress[0]
		intent.VerifyServerName = names[0]
	}
	payload, err := json.Marshal(intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, required_agent_id)
			 VALUES ($1, $2, $3, $4, $5)`,
			h.tenant, agentJobKindEndpointRenew, payload, idemKey, agentRowID(h.tenant, h.agent))
		return err
	}); err != nil {
		t.Fatalf("seed renewal job: %v", err)
	}
}

// claimOneRenewal claims the seeded job and returns it.
func claimOneRenewal(t *testing.T, ctx context.Context, h *roleHarness) transport.ClaimedJob {
	t.Helper()
	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{agentJobKindEndpointRenew}, Limit: 5, LeaseSeconds: 120,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed.Jobs) != 1 {
		t.Fatalf("claimed %d renewal jobs, want 1", len(claimed.Jobs))
	}
	return claimed.Jobs[0]
}

// The RPC is reachable on the served channel. A method registered on the
// descriptor but missing from the bulkhead wrapper would answer Unimplemented
// forever, which is the hazard the interface assertion exists to prevent — but
// an assertion only proves the method exists, not that it is wired to anything.
func TestServedSignJobCSRIsReachable(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)

	_, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{JobID: 1, CSRDER: []byte("x")})
	if err == nil {
		t.Fatal("a request for a job this agent does not hold was accepted")
	}
	if strings.Contains(err.Error(), "Unimplemented") || strings.Contains(err.Error(), "unknown method") {
		t.Fatalf("SignJobCSR is not served: %v", err)
	}
}

// An agent cannot get a certificate for a job it does not hold.
func TestServedSignJobCSRRefusesAJobTheAgentDoesNotHold(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)
	seedRenewalJob(t, ctx, h, "renew:unheld", []string{"api.example.test"})

	key, err := crypto.GenerateHostSubjectKey("api.example.test", []string{"api.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()

	// Never claimed. The job exists and is bound to exactly the name being
	// requested, so the ONLY thing refusing this is the holding check.
	if _, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{
		JobID: 1, Attempt: 1, CSRDER: key.CSRDER,
	}); err == nil {
		t.Fatal("a CSR for an unclaimed job was signed; holding the job is the whole authorization")
	}
}

// The name-widening attack, end to end against the running server.
func TestServedSignJobCSRRefusesANameOutsideTheBinding(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)
	seedRenewalJob(t, ctx, h, "renew:widen", []string{"api.example.test"})
	job := claimOneRenewal(t, ctx, h)

	// A legitimately held job, and a CSR asking for one extra name.
	key, err := crypto.GenerateHostSubjectKey("api.example.test",
		[]string{"api.example.test", "admin.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()

	if _, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{
		JobID: job.JobID, Attempt: job.Attempt, CSRDER: key.CSRDER,
	}); err == nil {
		t.Fatal("a CSR naming a host outside its binding was signed; an agent holding one " +
			"renewal could mint a certificate for any service it named")
	} else if !strings.Contains(err.Error(), "admin.example.test") {
		t.Errorf("the refusal did not name the offending host: %v", err)
	}
}

// The acceptance test: a whole renewal, then look for the key.
func TestServedHostGeneratedRenewalLeavesNoKeyMaterialBehind(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)
	seedRenewalJob(t, ctx, h, "renew:clean", []string{"api.example.test"})
	job := claimOneRenewal(t, ctx, h)

	key, err := crypto.GenerateHostSubjectKey("api.example.test", []string{"api.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()

	resp, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{
		JobID: job.JobID, Attempt: job.Attempt, CSRDER: key.CSRDER,
	})
	if err != nil {
		t.Fatalf("sign job csr: %v", err)
	}
	if len(resp.CertificatePEM) == 0 {
		t.Fatal("no certificate was returned")
	}
	if resp.Fingerprint == "" {
		t.Error("no fingerprint was returned, so the agent cannot verify what it installs")
	}

	// A retry of the SAME request returns the SAME certificate rather than
	// minting a second one. An agent holds exactly one key, and a second
	// certificate for a key it discarded is an orphan the estate never serves.
	again, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{
		JobID: job.JobID, Attempt: job.Attempt, CSRDER: key.CSRDER,
	})
	if err != nil {
		t.Fatalf("retry sign job csr: %v", err)
	}
	if again.Fingerprint != resp.Fingerprint {
		t.Errorf("a retried request minted a different certificate (%s then %s); an agent that "+
			"times out and retries would end up with a certificate it has no key for",
			resp.Fingerprint, again.Fingerprint)
	}

	// The custody claim must be PERSISTED, not merely assigned. B2's headline
	// is that the key was born on the host; if the column says nothing, an
	// auditor reading the database has no way to tell this certificate from one
	// the control plane generated, and the claim exists only in prose.
	var origin string
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		//trstctl:system-query — test-only read of this tenant's own certificate row.
		return tx.QueryRow(ctx,
			`SELECT coalesce(key_origin, '') FROM certificates
			  WHERE tenant_id = $1 AND fingerprint = $2`, h.tenant, resp.Fingerprint).Scan(&origin)
	}); err != nil {
		t.Fatalf("read recorded custody: %v", err)
	}
	if origin != string(custody.OriginHostAgent) {
		t.Errorf("recorded key_origin = %q, want %q; the certificate was issued against a CSR "+
			"an agent generated on its own host, and a custody column that does not say so "+
			"leaves the epic's central claim unverifiable from the database",
			origin, custody.OriginHostAgent)
	}

	// And now the claim itself: nothing in this tenant's durable state holds a
	// private key. This is what the whole epic is for.
	findings := assertNoPrivateKeyMaterial(t, ctx, h.store, h.tenant)
	for _, f := range findings {
		t.Errorf("private key material found in %s.%s (row %s, marker %q) after a renewal whose "+
			"key was generated on the host; B2's claim is that the control plane never holds it",
			f.Table, f.Column, f.RowRef, f.Marker)
	}
}

// The successful terminal report is the first moment the control plane can
// truthfully say where the host-generated key LIVES. Signing the CSR proves
// only where it was born; stamping "file" before the agent actually installs
// it would turn an install failure into false custody evidence.
func TestServedHostRenewalReceiptRequiresAndBindsCustodyAUD25(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)
	seedRenewalJob(t, ctx, h, "renew:custody-receipt", []string{"custody.example.test"}, "custody.example.test:443")
	job := claimOneRenewal(t, ctx, h)

	key, err := crypto.GenerateHostSubjectKey("custody.example.test", []string{"custody.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	issued, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{
		JobID: job.JobID, Attempt: job.Attempt, CSRDER: key.CSRDER,
	})
	if err != nil {
		t.Fatalf("sign renewal CSR: %v", err)
	}

	detail, digest := simulatedHostVerification(t, h, job, issued.Fingerprint, transport.JobOutcomeVerified)
	id := h.identity.Identity()
	omitted, err := transport.SignedReport(id, id.TenantID(), id.CommonName(), job.JobID, job.Attempt,
		transport.JobOutcomeVerified, detail, digest, time.Now().UTC().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.ReportJobResult(ctx, omitted); err == nil || !strings.Contains(err.Error(), "custody") {
		t.Fatalf("successful renewal without custody = %v, want custody refusal", err)
	}

	record := custody.Record{
		Origin: custody.OriginHostAgent, Storage: custody.StorageFile,
		Exportable: custody.Exportable, GeneratedBy: id.CommonName(),
	}
	wrongRecord := record
	wrongRecord.Storage = custody.StorageOSStore
	wrongRecord.Exportable = custody.NonExportable
	wrong, err := transport.SignedReportWithCustody(id, id.TenantID(), id.CommonName(), job.JobID, job.Attempt,
		transport.JobOutcomeVerified, detail, digest, issued.Fingerprint, wrongRecord, time.Now().UTC().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.ReportJobResult(ctx, wrong); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("agent-signed custody inconsistent with connector = %v, want semantic refusal", err)
	}

	tampered, err := transport.SignedReportWithCustody(id, id.TenantID(), id.CommonName(), job.JobID, job.Attempt,
		transport.JobOutcomeVerified, detail, digest, issued.Fingerprint, record, time.Now().UTC().Unix())
	if err != nil {
		t.Fatal(err)
	}
	tampered.Custody.Storage = custody.StorageOSStore
	if _, err := h.client.ReportJobResult(ctx, tampered); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered custody receipt = %v, want signature refusal", err)
	}

	valid, err := transport.SignedReportWithCustody(id, id.TenantID(), id.CommonName(), job.JobID, job.Attempt,
		transport.JobOutcomeVerified, detail, digest, issued.Fingerprint, record, time.Now().UTC().Unix())
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := h.client.ReportJobResult(ctx, valid)
	if err != nil || !accepted.Accepted {
		t.Fatalf("valid custody receipt = %+v, err=%v", accepted, err)
	}

	cert, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, issued.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if cert.KeyOrigin != string(record.Origin) || cert.KeyStorage != string(record.Storage) ||
		cert.KeyExportable != string(record.Exportable) || cert.KeyGeneratedBy != record.GeneratedBy {
		t.Fatalf("projected certificate custody = origin=%q storage=%q exportable=%q generated_by=%q",
			cert.KeyOrigin, cert.KeyStorage, cert.KeyExportable, cert.KeyGeneratedBy)
	}

	var statement, signature string
	var custodyEvent events.Event
	if err := h.log.Replay(ctx, 0, func(event events.Event) error {
		if event.TenantID != h.tenant {
			return nil
		}
		if event.Type == projections.EventCertificateCustodyAttested {
			custodyEvent = event
		}
		if event.Type != "agent.job.executed" {
			return nil
		}
		var payload map[string]any
		if json.Unmarshal(event.Data, &payload) == nil {
			statement, _ = payload["receipt_statement"].(string)
			signature, _ = payload["receipt_signature"].(string)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"credential_fingerprint=" + issued.Fingerprint,
		"key_origin=host_agent", "key_storage=file", "key_exportable=exportable",
		"key_generated_by=" + id.CommonName(),
	} {
		if !strings.Contains(statement, want) {
			t.Errorf("durable signed receipt statement missing %q:\n%s", want, statement)
		}
	}
	if custodyEvent.ID == "" {
		t.Fatal("verified receipt did not append certificate.custody.attested")
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	if err := mtls.VerifyStatement(id.CertificateDER(), []byte(statement), sig); err != nil {
		t.Fatalf("persisted custody statement is not independently verifiable: %v", err)
	}
	// A full rebuild atomically replaces both projections and their completion
	// receipts. Replaying a completed event alone is deliberately inert; it is
	// not a recovery primitive for manually damaged SQL fields.
	projector := projections.New(h.store)
	if err := projector.Rebuild(ctx, h.log); err != nil {
		t.Fatalf("full custody rebuild: %v", err)
	}
	assertCustody := func(stage string) {
		t.Helper()
		rebuilt, err := h.store.GetCertificateByFingerprint(ctx, h.tenant, issued.Fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		if rebuilt.KeyOrigin != cert.KeyOrigin || rebuilt.KeyStorage != cert.KeyStorage ||
			rebuilt.KeyExportable != cert.KeyExportable || rebuilt.KeyGeneratedBy != cert.KeyGeneratedBy ||
			rebuilt.Fingerprint != cert.Fingerprint || rebuilt.ValidityAnchor == nil || cert.ValidityAnchor == nil ||
			!rebuilt.ValidityAnchor.Equal(*cert.ValidityAnchor) {
			t.Fatalf("%s custody = %+v, want %+v", stage, rebuilt, cert)
		}
	}
	assertCustody("full rebuild")
	if err := projector.Apply(ctx, custodyEvent); err != nil {
		t.Fatalf("replay custody attestation: %v", err)
	}
	assertCustody("exact duplicate")
}

// The name-widening attack via NON-DNS identifiers (epic B2).
//
// The subset rule originally read only DNSNames and the CommonName, but
// crypto.SignLeafFromCSRWithProfile copies csr.IPAddresses, csr.EmailAddresses
// and csr.URIs verbatim into the leaf. So an agent holding a perfectly
// legitimate renewal for one DNS name could have obtained a certificate
// asserting an IP address or a spiffe:// URI it was never bound to — the exact
// escalation the authorization rule exists to prevent, through a door the rule
// was not looking at.
//
// A renewal binding names DNS hosts and can express nothing else, so these are
// refused outright rather than compared against it.
func TestServedSignJobCSRRefusesNonDNSIdentifiers(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name   string
		mutate func(*crypto.CertificateRequestTemplate)
		want   string
	}{
		{
			name: "ip address SAN",
			mutate: func(tmpl *crypto.CertificateRequestTemplate) {
				tmpl.IPAddresses = []net.IP{net.ParseIP("10.0.0.7")}
			},
			want: "10.0.0.7",
		},
		{
			name: "spiffe URI SAN",
			mutate: func(tmpl *crypto.CertificateRequestTemplate) {
				tmpl.URIs = []string{"spiffe://prod/ns/payments/sa/admin"}
			},
			want: "spiffe://",
		},
		{
			name: "email SAN",
			mutate: func(tmpl *crypto.CertificateRequestTemplate) {
				tmpl.EmailAddresses = []string{"ceo@other.example"}
			},
			want: "ceo@other.example",
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			h := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)
			seedRenewalJob(t, ctx, h, "renew:"+tc.name, []string{"api.example.test"})
			job := claimOneRenewal(t, ctx, h)

			csrDER := csrWithExtraSAN(t, "api.example.test", tc.mutate)

			_, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{
				JobID: job.JobID, Attempt: job.Attempt, CSRDER: csrDER,
			})
			if err == nil {
				t.Fatalf("a CSR asserting %s alongside its bound DNS name was signed; an agent "+
					"holding one legitimate renewal could certify an identifier it was never "+
					"bound to", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal did not name the offending identifier %q: %v", tc.want, err)
			}
		})
	}
}

// csrWithExtraSAN builds a CSR for commonName plus whatever mutate adds.
//
// Built through internal/crypto (AN-3) rather than crypto/x509 directly — the
// boundary rule holds for tests, and the template already expresses every SAN
// type, so there was never a reason to reach around it. The point of the helper
// is to construct a request a COMPLIANT agent would never make:
// GenerateHostSubjectKey only ever sets a CN and DNS names, so the threat model
// here — an agent that has been modified — needs a way to build the request that
// agent cannot.
func csrWithExtraSAN(t *testing.T, commonName string, mutate func(*crypto.CertificateRequestTemplate)) []byte {
	t.Helper()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Destroy()

	tmpl := crypto.CertificateRequestTemplate{
		CommonName: commonName,
		DNSNames:   []string{commonName},
	}
	mutate(&tmpl)
	der, err := crypto.CreateCertificateRequest(tmpl, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// One claim authorizes one key, not unlimited certificates (epic B2).
//
// The idempotency key is derived from the CSR's own bytes, which is what makes a
// timed-out retry return the certificate the agent already holds. Left alone,
// that same property means every NEW key is a new issuance — so one legitimately
// claimed job could mint certificates for as long as its lease lasts, which is
// exactly what a compromised or looping agent would do.
//
// The two cases have to be told apart, so this test asserts both halves: the
// same request replays, a different one is refused.
func TestOneClaimAuthorizesOneKey(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)
	seedRenewalJob(t, ctx, h, "renew:onekey", []string{"api.example.test"})
	job := claimOneRenewal(t, ctx, h)

	first, err := crypto.GenerateHostSubjectKey("api.example.test", []string{"api.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Destroy()

	got, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{
		JobID: job.JobID, Attempt: job.Attempt, CSRDER: first.CSRDER,
	})
	if err != nil {
		t.Fatalf("first signature: %v", err)
	}

	// The retry half: the SAME request must return the SAME certificate. An
	// agent whose call timed out still holds exactly one key, and refusing here
	// would lose its certificate over a network blip.
	replay, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{
		JobID: job.JobID, Attempt: job.Attempt, CSRDER: first.CSRDER,
	})
	if err != nil {
		t.Fatalf("a retry of the same request was refused: %v; the agent holds a key whose "+
			"certificate it can now never collect", err)
	}
	if replay.Fingerprint != got.Fingerprint {
		t.Errorf("a retried request minted a different certificate (%s then %s)",
			got.Fingerprint, replay.Fingerprint)
	}

	// The abuse half: a DIFFERENT key on the same claim is refused.
	second, err := crypto.GenerateHostSubjectKey("api.example.test", []string{"api.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Destroy()
	if _, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{
		JobID: job.JobID, Attempt: job.Attempt, CSRDER: second.CSRDER,
	}); err == nil {
		t.Fatal("a second, different key was certified against one claimed job; one claim would " +
			"authorize unbounded issuance for the life of its lease")
	}
}

// The attempt binding must not be optional (epic B2).
//
// The check used to read `req.Attempt > 0 && job.ClaimAttempts > 0`, so an agent
// sending Attempt=0 skipped it entirely. A check a caller can decline is not a
// check — and what it guards is real: a CSR built under a lapsed lease being
// signed after the work was reassigned, leaving two hosts serving one endpoint.
func TestTheAttemptBindingCannotBeDeclined(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleHost}, agentJobKindEndpointRenew)
	seedRenewalJob(t, ctx, h, "renew:attempt", []string{"api.example.test"})
	job := claimOneRenewal(t, ctx, h)

	key, err := crypto.GenerateHostSubjectKey("api.example.test", []string{"api.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()

	if _, err := h.client.SignJobCSR(ctx, &transport.SignJobCSRRequest{
		JobID: job.JobID, Attempt: 0, CSRDER: key.CSRDER,
	}); err == nil {
		t.Fatal("a request declaring attempt 0 was signed against a live claim; an agent could " +
			"opt out of the attempt binding by simply not sending one")
	}
}
