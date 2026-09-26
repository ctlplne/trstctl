// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/pqc"
)

// Exercise a real signature followed by cancellation before certificate.recorded.
// Existing recovery tests start after that event and cannot cover this gap.
func TestServedPQCFirstLeafRetryDoesNotSignAgainAfterLostRecording(t *testing.T) {
	for _, algorithm := range []crypto.Algorithm{pqc.MLDSA44, pqc.MLDSA65, pqc.MLDSA87} {
		t.Run(string(algorithm), func(t *testing.T) { testPQCFirstLeafLostRecording(t, algorithm) })
	}
}

// Real PG/NATS and persistent signing RPC; the fixture signer is in a goroutine,
// so this is recovery proof, not process-isolation or connector-deployment proof.
func testPQCFirstLeafLostRecording(t *testing.T, algorithm crypto.Algorithm) {
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.LicensedCSRParser = pqc.ParsePureMLDSACSR
		d.LicensedCSRInspector = pqc.InspectHybridCSR
		d.LicensedLeafSigner = pqc.SignLicensedLeafFromCSRWithProfile
		d.PreparedSubjectLeafSigner = pqc.SignPQCLeafFromCSRWithPreparation
	})
	token := seedScopedToken(t, h.store, h.tenant, "owners:write", "identities:write", "certs:read", "certs:issue")
	owner := servedCreateID(t, h, token, "sign-gap-owner", "/api/v1/owners", map[string]any{
		"kind": "workload", "name": "sign-gap", "email": "owner@example.test",
		"application_id": "sign-gap", "environment": "test",
	})
	id := servedCreateID(t, h, token, "sign-gap-identity", "/api/v1/identities", map[string]any{
		"kind": "x509_certificate", "name": "sign-gap.example.test", "owner_id": owner,
	})
	request := map[string]any{"to": "issued"}
	key, err := pqc.GenerateHostMLDSASubjectKey(crypto.CertificateRequestTemplate{CommonName: "sign-gap.example.test", DNSNames: []string{"sign-gap.example.test"}}, algorithm)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	bad := bytes.Clone(key.CSRDER)
	bad[len(bad)-1] ^= 1
	rejected, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+id+"/transitions", token, "sign-gap-invalid-proof", map[string]any{
		"to": "issued", "subject_csr_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: bad})),
	})
	if rejected != http.StatusBadRequest {
		t.Fatalf("invalid PQC proof must fail at API edge: %d", rejected)
	}
	request["subject_csr_pem"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: key.CSRDER}))
	status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/identities/"+id+"/transitions", token, "sign-gap-transition", request)
	if status != http.StatusOK {
		t.Fatalf("accept issuance: %d %s", status, body)
	}
	d := h.srv.obHandler.(*issuanceDispatcher)
	issue := d.issue
	var cancelAfterSign context.CancelFunc
	var issued []crypto.IssuedLeaf
	var originalCSR []byte
	var originalTTL time.Duration
	var originalProfile crypto.LeafProfile
	d.issue = func(ctx context.Context, csr []byte, ttl time.Duration, profile crypto.LeafProfile) (crypto.IssuedLeaf, error) {
		originalCSR, originalTTL, originalProfile = append([]byte(nil), csr...), ttl, profile
		leaf, err := issue(ctx, csr, ttl, profile)
		if err == nil {
			issued = append(issued, leaf)
			if len(issued) == 1 {
				cancelAfterSign()
			}
		}
		return leaf, err
	}
	box := orchestrator.NewOutbox(h.store, orchestrator.WithBackoff(func(int) time.Duration { return 0 }), orchestrator.WithMaxAttempts(2))
	for attempt := 1; attempt <= 2; attempt++ {
		did, err := box.DispatchOneScoped(t.Context(), orchestrator.HandlerFunc(func(ctx context.Context, message orchestrator.Message) error {
			if message.IdempotencyKey != "transition:sign-gap-transition" || message.Attempts != attempt {
				t.Fatalf("wrong receiver claim: key=%s attempts=%d", message.IdempotencyKey, message.Attempts)
			}
			requestContext, cancel := context.WithCancel(ctx)
			defer cancel()
			cancelAfterSign = cancel
			err := d.Deliver(requestContext, message)
			if attempt == 1 && !errors.Is(err, context.Canceled) {
				t.Errorf("first request did not fail after signing: %v", err)
			}
			if attempt == 2 && err != nil {
				t.Errorf("retry did not complete: %v", err)
			}
			return err
		}), orchestrator.DestinationScope{IncludePrefixes: []string{"ca.issue"}})
		if err != nil || !did {
			t.Fatalf("dispatch %d: %t %v", attempt, did, err)
		}
	}
	if len(issued) != 2 || !bytes.Equal(issued[0].DER, issued[1].DER) {
		t.Fatalf("retry must return the byte-identical certificate after lost recording; received %d results", len(issued))
	}
	state, err := d.orch.State(t.Context(), h.tenant, id)
	// No connector was requested. A signed/downloadable leaf remains issued;
	// inventing a deployment here would itself be an incorrect success claim.
	if err != nil || state != orchestrator.StateIssued {
		t.Fatalf("recovered issuance state=%s err=%v; want issued", state, err)
	}
	certs, err := recoverCertificatesByIssuanceKey(t.Context(), h.store, h.log, h.tenant, "issue:transition:sign-gap-transition")
	if err != nil || len(certs) != 1 || !bytes.Equal(certs[0].CertificateDER, issued[0].DER) {
		t.Fatalf("recovery inventory must contain only the original leaf: count=%d err=%v", len(certs), err)
	}
	if certs[0].KeyOrigin != "requester" || certs[0].KeyAlgorithm != string(algorithm) {
		t.Fatalf("original subject custody or algorithm changed: origin=%s algorithm=%s", certs[0].KeyOrigin, certs[0].KeyAlgorithm)
	}
	// A fresh receiver object has no in-memory knowledge of the first call.
	// Changed CSR/profile requests under the same original operation must fail
	// before another signature, including when the original result is retained.
	ctx := withLeafCommand(t.Context(), orchestrator.NewIdempotency(h.store), h.tenant, "transition:sign-gap-transition")
	changedCSR, _, err := decodeSubjectCSR(subjectCSR(t, "changed.example.test"))
	if err != nil {
		t.Fatal(err)
	}
	if leaf, err := h.srv.issueLeafWithValidity(ctx, changedCSR, originalTTL, originalProfile); !errors.Is(err, orchestrator.ErrIdempotencyConflict) || len(leaf.DER) != 0 {
		t.Fatalf("changed CSR did not fail at the retained request binding: %v", err)
	}
	changedProfile := originalProfile
	changedProfile.AllowedExtKeyUsage = []string{"serverAuth"}
	if leaf, err := h.srv.issueLeafWithValidity(ctx, originalCSR, originalTTL, changedProfile); !errors.Is(err, orchestrator.ErrIdempotencyConflict) || len(leaf.DER) != 0 {
		t.Fatalf("changed profile did not fail at the retained request binding: %v", err)
	}
}
