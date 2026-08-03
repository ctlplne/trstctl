// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/aimodel"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/events"
)

// Just-in-time credential redemption, proven on the assembled binary (epic A3).
//
// The claim hands a relay a REFERENCE. The relay redeems it over the channel it
// already authenticated on, once, and the material exists outside the seal only
// for that one attempt. These drive the whole path and then go looking for the
// credential everywhere it could have leaked.

// canaryKeyPEM is high-entropy, so the residual-secret scanner fires on it.
// canaryPassword is short and word-shaped, so it does NOT trip the entropy
// floors — it proves the named-canary layer is load-bearing rather than
// redundant. Both must be absent from every artifact.
const (
	canaryKeyPEM   = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\nMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\nNMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ\n-----END PRIVATE KEY-----"
	canaryPassword = "hunter2-lab"
)

// TestServedRelayRedeemsOnceAndTheCredentialNeverLeaks is A3 acceptance #1 and
// #2 together: a relay claims a credential-bearing job, redeems the material,
// cannot redeem it again, and neither canary appears in any job row, any event,
// any served receipt, or the agent's own report.
func TestServedRelayRedeemsOnceAndTheCredentialNeverLeaks(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, "connector.deploy")

	jobID := seedSealedRelayJob(t, ctx, h)

	claimed, err := h.client.ClaimJobs(ctx, &transport.ClaimJobsRequest{
		Kinds: []string{"connector.deploy"}, Limit: 5, LeaseSeconds: 120,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed.Jobs) != 1 {
		t.Fatalf("relay claimed %d jobs, want 1", len(claimed.Jobs))
	}
	job := claimed.Jobs[0]
	if job.JobID != jobID {
		t.Fatalf("claimed job %d, want %d", job.JobID, jobID)
	}

	// The claim envelope itself must carry no credential: the relay learns what
	// to deploy, not what to deploy WITH, until it redeems.
	assertNoCanary(t, "claimed job payload", job.Payload)

	redeemed, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{
		JobID: job.JobID, Attempt: job.Attempt,
	})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if redeemed.AuditRef == "" {
		t.Fatal("granted redemption carries no audit ref for the console to show")
	}
	if redeemed.ExpiresUnix > job.LeaseExpiresUnix {
		t.Fatalf("redemption expiry %d outlives the claim lease %d", redeemed.ExpiresUnix, job.LeaseExpiresUnix)
	}
	// The material actually arrived — otherwise every leak assertion below would
	// pass for the wrong reason.
	byName := map[string][]byte{}
	for _, item := range redeemed.Items {
		byName[item.Name] = item.Value
	}
	if !bytes.Contains(byName["credential.key_pem"], []byte(canaryKeyPEM)) {
		t.Fatalf("redeemed key material does not carry the canary; got %d items %v", len(redeemed.Items), keysOf(byName))
	}
	if !bytes.Contains(byName["secret://relay-appliance-admin"], []byte(canaryPassword)) {
		t.Fatalf("redeemed target secret does not carry the password canary; got %v", keysOf(byName))
	}

	// Acceptance #2: a replay of the same attempt fails closed, and hands back
	// nothing at all.
	replay, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{
		JobID: job.JobID, Attempt: job.Attempt,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("replayed redemption error = %v (%v), want PermissionDenied", err, status.Code(err))
	}
	if replay != nil && len(replay.Items) != 0 {
		t.Fatal("refused redemption still returned material")
	}
	if !h.hasEvent(t, "agent.job.credential.redemption_refused") {
		t.Fatal("a refused redemption left no evidence")
	}
	if !h.hasEvent(t, "agent.job.credential.redeemed") {
		t.Fatal("a granted redemption left no evidence")
	}

	// The agent reports failure with a hostile detail: a real appliance can echo
	// the credential it was just handed back in an error body, and the closed-set
	// last_error discipline exists for exactly that.
	if _, err := h.client.ReportJobResult(ctx, h.report(t, job.JobID, job.Attempt,
		transport.JobOutcomeFailed,
		"appliance rejected the upload: "+canaryPassword+" / "+canaryKeyPEM, "")); err != nil {
		t.Fatalf("report: %v", err)
	}

	// Acceptance #1: sweep every sink.
	assertNoCanaryInJobRows(t, ctx, h)
	assertNoCanaryInEvents(t, ctx, h)
}

// TestServedRedemptionRequiresTheLease: an agent that never claimed the job
// cannot redeem it, even holding the right role and asking for the right
// attempt.
func TestServedRedemptionRequiresTheLease(t *testing.T) {
	ctx := context.Background()
	h := newRoleHarness(t, []string{mtls.AgentRoleNetwork}, "connector.deploy")
	jobID := seedSealedRelayJob(t, ctx, h)

	// No claim at all — straight to redemption.
	if _, err := h.client.RedeemJobCredential(ctx, &transport.RedeemJobCredentialRequest{
		JobID: jobID, Attempt: 1,
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unclaimed redemption error = %v (%v), want PermissionDenied", err, status.Code(err))
	}
	assertNoCanaryInEvents(t, ctx, h)
}

// seedSealedRelayJob enqueues a relay-vantage connector.deploy carrying sealed
// credential material and a secret:// reference, the way the issuance
// dispatcher does, and returns the job id.
func seedSealedRelayJob(t *testing.T, ctx context.Context, h *roleHarness) int64 {
	t.Helper()
	const (
		idemKey     = "relay-deploy:edge-f5"
		destination = "connector.deploy"
		secretName  = "relay-appliance-admin"
	)
	// The appliance password lives in the tenant's secret store, referenced by
	// the target config exactly as a real target would.
	sealedSecret, err := h.srv.sealTenantSecretForTest(ctx, h.tenant, secretName, []byte(canaryPassword))
	if err != nil {
		t.Fatalf("seal tenant secret: %v", err)
	}
	if _, err := h.store.PutSecret(ctx, h.tenant, secretName, sealedSecret); err != nil {
		t.Fatalf("put tenant secret: %v", err)
	}

	targetConfig, cfgErr := json.Marshal(map[string]any{
		"base_url": "https://f5.example.internal",
		"password": "secret://" + secretName,
	})
	if cfgErr != nil {
		t.Fatal(cfgErr)
	}
	raw, marshalErr := json.Marshal(connector.DeployPayload{
		Connector:    "f5",
		Target:       "edge-f5",
		TargetConfig: targetConfig,
		CertPEM:      []byte("-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----"),
		KeyPEM:       []byte(canaryKeyPEM),
		Fingerprint:  "ff00",
	})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	sealed, sealErr := h.srv.sealRelayDeployForTest(ctx, h.tenant, destination, idemKey, raw)
	if sealErr != nil {
		t.Fatalf("seal deploy payload: %v", sealErr)
	}

	var jobID int64
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO outbox (tenant_id, destination, payload, idempotency_key, required_agent_role)
			 VALUES ($1, $2, $3, $4, 'network') RETURNING id`,
			h.tenant, destination, sealed, idemKey).Scan(&jobID)
	}); err != nil {
		t.Fatalf("seed sealed relay job: %v", err)
	}
	return jobID
}

// assertNoCanary fails if either canary appears in the artifact, in raw, base64,
// or hex form — the credential crosses JSON boundaries where []byte marshals to
// base64, so a raw-bytes-only check would silently miss it.
func assertNoCanary(t *testing.T, label string, haystack []byte) {
	t.Helper()
	assertNoCanaryBytes(t, label, haystack)
	// The entropy scanner catches a shape the named canaries would miss — a
	// credential that leaked in some re-encoded form.
	if aimodel.ResidualSecret(string(haystack)) {
		t.Errorf("%s contains residual secret-like material after redaction", label)
	}
}

// assertNoCanaryBytes is the named-canary half, for artifacts that are
// legitimately high-entropy (digests, UUIDs) and would trip the entropy scanner
// no matter how clean they are.
func assertNoCanaryBytes(t *testing.T, label string, haystack []byte) {
	t.Helper()
	for _, canary := range []string{canaryKeyPEM, canaryPassword} {
		raw := []byte(canary)
		encodings := map[string][]byte{
			"raw":    raw,
			"base64": []byte(base64.StdEncoding.EncodeToString(raw)),
			"hex":    []byte(hex.EncodeToString(raw)),
		}
		for form, needle := range encodings {
			if bytes.Contains(haystack, needle) {
				t.Errorf("%s contains the credential canary (%s form)", label, form)
			}
		}
	}
}

// assertNoCanaryInJobRows sweeps the durable ledger: the outbox row's payload
// and last_error, and the redemption ledger's own columns.
func assertNoCanaryInJobRows(t *testing.T, ctx context.Context, h *roleHarness) {
	t.Helper()
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT coalesce(last_error, ''), coalesce(required_agent_role, '')
			   FROM outbox WHERE tenant_id = $1`, h.tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var lastError, role string
			if err := rows.Scan(&lastError, &role); err != nil {
				return err
			}
			assertNoCanary(t, "outbox.last_error", []byte(lastError))
			assertNoCanary(t, "outbox.required_agent_role", []byte(role))
		}
		if err := rows.Err(); err != nil {
			return err
		}
		redemptions, err := tx.Query(ctx,
			`SELECT encode(binding, 'hex'), audit_ref::text
			   FROM agent_job_credential_redemptions WHERE tenant_id = $1`, h.tenant)
		if err != nil {
			return err
		}
		defer redemptions.Close()
		for redemptions.Next() {
			var binding, auditRef string
			if err := redemptions.Scan(&binding, &auditRef); err != nil {
				return err
			}
			// The binding is a SHA-256 digest and the audit ref is a UUID: both
			// are high-entropy BY DESIGN, so the entropy scanner would flag them
			// forever. What matters is that neither contains the credential, so
			// they get the canary check without the entropy check.
			assertNoCanaryBytes(t, "redemption.binding", []byte(binding))
			assertNoCanaryBytes(t, "redemption.audit_ref", []byte(auditRef))
		}
		return redemptions.Err()
	}); err != nil {
		t.Fatalf("sweep job rows: %v", err)
	}
}

// assertNoCanaryInEvents sweeps the whole tenant event log — the redemption
// events, the refusal events, and the job failure event carrying the agent's
// hostile detail.
func assertNoCanaryInEvents(t *testing.T, ctx context.Context, h *roleHarness) {
	t.Helper()
	if err := h.log.Replay(ctx, 0, func(e events.Event) error {
		if e.TenantID != h.tenant {
			return nil
		}
		// The NAMED canaries are checked against the whole payload, receipt
		// fields included — nothing is exempt from "does this contain the
		// credential".
		assertNoCanaryBytes(t, "event "+e.Type, e.Data)
		// The entropy scanner runs on everything EXCEPT the signed receipt
		// (epic A1), for the same reason it already skips digests and UUIDs:
		// a signature, a canonical statement full of hashes, and a certificate
		// fingerprint are high-entropy by construction and public by
		// construction. Exempting them from an entropy heuristic is not a hole
		// — the named-canary sweep above still reads them, and the statement's
		// own content is a closed set of fields this code builds, never
		// anything an agent supplied.
		assertNoCanary(t, "event "+e.Type, withoutReceiptFields(t, e.Data))
		return nil
	}); err != nil {
		t.Fatalf("replay events: %v", err)
	}
}

// withoutReceiptFields removes the signed-receipt fields from an event payload
// so the entropy heuristic reads only the parts that could plausibly carry a
// re-encoded credential.
func withoutReceiptFields(t *testing.T, payload []byte) []byte {
	t.Helper()
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		// Not an object: nothing to strip, scan it whole.
		return payload
	}
	for _, field := range []string{"receipt_statement", "receipt_signature", "receipt_signer_fingerprint"} {
		delete(decoded, field)
	}
	stripped, err := json.Marshal(decoded)
	if err != nil {
		return payload
	}
	return stripped
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
