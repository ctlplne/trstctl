// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/attest/tpmquote"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
)

// TestVH38AttestedProofReplayMintsForAttackerKey (R1 verifier VH38, leads LT1a B3c
// and B3a). One served harness, tenant-managed trust sources created through the
// public API, and the public attested-issuance route. For each method a legitimate
// workload first issues with its proof and its own key; a second caller then replays
// the SAME captured proof under a new Idempotency-Key with a key of its choosing.
// The replay must be refused:
//   - tpm (B3c): the trust source carries expected_nonce_base64, which the docs call
//     "a signed quote bound to a fresh nonce"; a fresh nonce cannot accept a replay.
//   - aws_iid and azure_imds (B3a): the instance identity documents never expire
//     and bind no key, so without a one-time fence they are bearer proofs.
//   - k8s_sat (B3a): the service-account token is bound to no key either.
func TestVH38AttestedProofReplayMintsForAttackerKey(t *testing.T) {
	newKey := func() (string, []byte) {
		t.Helper()
		k, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(k.Destroy)
		return string(crypto.MarshalPublicKeyPEM(k.Public().DER)), append([]byte(nil), k.Public().DER...)
	}
	certPEM := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}

	// TPM manufacturer root, an endorsed AK, and one quote over the operator's nonce.
	manu, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manu.Destroy)
	manuCert, err := crypto.SelfSignedCACert(manu, "VH38 TPM Manufacturer", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ak, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ak.Destroy)
	akCSR, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "AK"}, ak)
	if err != nil {
		t.Fatal(err)
	}
	akCert, err := crypto.SignLeafFromCSR(manuCert, manu, akCSR, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("vh38-operator-nonce")
	msg := append([]byte("PCR0:abcd|nonce:"), nonce...)
	sig, err := crypto.SignMessage(ak, msg)
	if err != nil {
		t.Fatal(err)
	}
	quote, err := json.Marshal(tpmquote.Quote{AKCertDER: akCert, Message: msg, Signature: sig, Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}

	// AWS instance identity document (PKCS#7, no expiry, no nonce).
	awsDoc := []byte(`{"instanceId":"i-0vh38","accountId":"111122223333","region":"us-east-1","instanceType":"m5.large","imageId":"ami-1","pendingTime":"2026-01-01T00:00:00Z"}`)
	awsIID, awsRoot, err := crypto.SignCMS(awsDoc)
	if err != nil {
		t.Fatal(err)
	}
	azureDoc := []byte(`{"vmId":"vh38-vm","subscriptionId":"sub-vh38","resourceGroupName":"rg","location":"eastus","name":"web"}`)
	azureIMDS, azureRoot, err := crypto.SignCMS(azureDoc)
	if err != nil {
		t.Fatal(err)
	}
	azureIMDS2, azureRoot2, err := crypto.SignCMS(azureDoc)
	if err != nil {
		t.Fatal(err)
	}

	k8s := servedDynamicK8sTrustFixture(t, "vh38-k8s")

	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AttestedIssuance = AttestedIssuanceConfig{
			Enabled: true, TrustDomain: "served.test", DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour,
		}
	})
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "vh38-trust-admin@example.test",
		"certs:issue", "certs:read", "issuers:read", "issuers:write")
	for _, src := range []map[string]any{
		{"name": "vh38-tpm", "method": "tpm", "root_certs_pem": []string{certPEM(manuCert)},
			"expected_nonce_base64": base64.StdEncoding.EncodeToString(nonce)},
		{"name": "vh38-aws", "method": "aws_iid", "root_certs_pem": []string{certPEM(awsRoot)}},
		{"name": "vh38-azure", "method": "azure_imds", "root_certs_pem": []string{certPEM(azureRoot), certPEM(azureRoot2)}},
		{"name": "vh38-k8s", "method": "k8s_sat", "issuer": "https://kubernetes.default.svc",
			"audience": "trstctl", "jwks": k8s.JWKS},
	} {
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources",
			admin, "vh38-create-"+src["name"].(string), src)
		if status != http.StatusCreated {
			t.Fatalf("create %s trust source: %d %s", src["method"], status, body)
		}
	}
	issuer := seedScopedToken(t, h.store, h.tenant, "certs:issue", "certs:read")

	for _, tc := range []struct {
		lead, method string
		proof        []byte
	}{
		{"B3c", "tpm", quote},
		{"B3a", "aws_iid", awsIID},
		{"B3a", "azure_imds", azureIMDS},
		{"B3a", "k8s_sat", []byte(k8s.SAT)},
	} {
		t.Run(tc.method, func(t *testing.T) {
			ownerPEM, _ := newKey()
			first := servedAttestedIssue(t, h, issuer, "vh38-"+tc.method+"-owner", tc.method, tc.proof, ownerPEM, http.StatusCreated)
			proofKey, err := attestedProofKey(h.tenant, attest.Attestation{Method: tc.method, Subject: first.Attestation.Subject}, tc.proof)
			if err != nil {
				t.Fatal(err)
			}
			// A bounded bookkeeping row may be swept. The retained certificate
			// event must still own this proof's issuance slot after that sweep.
			if err := h.store.WithTenant(t.Context(), h.tenant, func(tx pgx.Tx) error {
				_, err := tx.Exec(t.Context(), `DELETE FROM idempotency_keys WHERE tenant_id=$1 AND key=$2`,
					h.tenant, "attested-proof-template:v1:"+proofKey)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			attackerPEM, attackerDER := newKey()
			replayProof := tc.proof
			if tc.method == "azure_imds" {
				// The same VM can present a newly signed but equally timeless
				// document. A raw-envelope digest must not allocate a new slot.
				replayProof = azureIMDS2
			}
			status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attested-issuance", issuer,
				"vh38-"+tc.method+"-replay", map[string]any{
					"method":         tc.method,
					"payload_base64": base64.StdEncoding.EncodeToString(replayProof),
					"public_key_pem": attackerPEM,
					"ttl_seconds":    600,
				})
			if status == http.StatusCreated {
				var got servedAttestedIssueResponse
				if err := json.Unmarshal(body, &got); err != nil {
					t.Fatalf("decode replay response: %v", err)
				}
				block, _ := pem.Decode([]byte(got.CertificatePEM))
				if block == nil {
					t.Fatalf("replay returned 201 without a certificate: %s", body)
				}
				certKey, err := crypto.PublicKeyDERFromCert(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				t.Errorf("%s %s: captured proof minted a second SVID for another key (cert key == replayer key: %v); owner identity %s; replay identity %s; claims %v",
					tc.lead, tc.method, bytes.Equal(certKey, attackerDER), first.SPIFFEID, got.SPIFFEID, got.Attestation.Claims)
			} else if status != http.StatusConflict {
				t.Fatalf("%s %s: replay status %d, want 409; body=%s", tc.lead, tc.method, status, body)
			}
			retry := servedAttestedIssue(t, h, issuer, "vh38-"+tc.method+"-same-key-retry", tc.method, tc.proof, ownerPEM, http.StatusCreated)
			if retry.CertificatePEM != first.CertificatePEM || retry.CredentialID != first.CredentialID ||
				!retry.Attestation.VerifiedAt.Equal(first.Attestation.VerifiedAt) {
				t.Fatalf("%s %s: same proof and key under new HTTP retry key minted another certificate", tc.lead, tc.method)
			}
		})
	}
}

func TestCR331ConcurrentReplicasCannotMintDifferentKeysFromOneProof(t *testing.T) {
	k8s := servedDynamicK8sTrustFixture(t, "cr331-replica")
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.AttestedIssuance = AttestedIssuanceConfig{
			Enabled: true, TrustDomain: "served.test", DefaultTTL: 10 * time.Minute, MaxTTL: time.Hour,
		}
	})
	admin := seedScopedTokenSubject(t, h.store, h.tenant, "cr331-trust-admin@example.test",
		"certs:issue", "certs:read", "issuers:read", "issuers:write")
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources",
		admin, "cr331-replica-trust", map[string]any{
			"name": "cr331-replica", "method": "k8s_sat", "issuer": "https://kubernetes.default.svc",
			"audience": "trstctl", "jwks": k8s.JWKS,
		})
	if status != http.StatusCreated {
		t.Fatalf("create trust: %d %s", status, body)
	}
	peer := *h.srv.attestedIssuance
	peer.idem = orchestrator.NewIdempotency(h.store)
	services := []*attestedIssuerService{h.srv.attestedIssuance, &peer}
	requests := make([]api.AttestedSVIDRequest, 2)
	for i := range requests {
		public, err := crypto.ParsePublicKeyPEM([]byte(servedAttestedPublicKeyPEM(t)))
		if err != nil {
			t.Fatal(err)
		}
		requests[i] = api.AttestedSVIDRequest{Method: "k8s_sat", Payload: []byte(k8s.SAT), PublicKeyDER: public.DER, TTLSeconds: 600}
	}
	type result struct {
		issued api.AttestedSVID
		err    error
	}
	start := make(chan struct{})
	outcomes := make(chan result, 2)
	keys := [2]string{"cr331-replica-left", "cr331-replica-right"}
	for i := range requests {
		go func() {
			<-start
			issued, err := services[i].IssueAttestedSVID(t.Context(), h.tenant, keys[i], requests[i])
			outcomes <- result{issued: issued, err: err}
		}()
	}
	close(start)
	issued, refused := 0, 0
	for range requests {
		got := <-outcomes
		switch {
		case got.err == nil && got.issued.CredentialID != "":
			issued++
		case errors.Is(got.err, orchestrator.ErrIdempotencyConflict):
			refused++
		default:
			t.Errorf("unexpected concurrent result: %v", got.err)
		}
	}
	if issued != 1 || refused != 1 || servedCertificateCountAUD47(t, h) != 1 {
		t.Fatalf("concurrent results issued=%d refused=%d; want one leaf and one conflict", issued, refused)
	}
}
