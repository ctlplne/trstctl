// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

type unavailableDeploymentSealer struct {
	sealKeyWrapper
	unavailable bool
	refuseOpen  bool
}

func (k *unavailableDeploymentSealer) UnwrapDEK(wrapped []byte) ([]byte, error) {
	if k.refuseOpen {
		return nil, errors.New("QA: retained subject cannot be unsealed")
	}
	return k.sealKeyWrapper.UnwrapDEK(wrapped)
}

func (k *unavailableDeploymentSealer) WrapDEK(raw []byte) ([]byte, error) {
	if k.unavailable {
		return nil, errors.New("QA: deployment sealing temporarily unavailable")
	}
	return k.sealKeyWrapper.WrapDEK(raw)
}

// The first public certificate is durable, but deployment sealing fails before
// identity.deployed can append its intent. Recovering only the certificate is
// insufficient: the original ca.issue delivery still owes its deployment.
func TestFirstLeafRetryFinishesDeploymentAfterRecording(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := t.Context()
	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "deployment-gap-owner", "")
	if err != nil {
		t.Fatal(err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "deployment-gap.example.test", OwnerID: owner.ID,
		Attributes: json.RawMessage(`{"connector":"nginx","target":"qa-deployment-gap"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.orch.TransitionWithIdempotency(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "issue and deploy", "deployment-gap"); err != nil {
		t.Fatal(err)
	}
	sealer := &unavailableDeploymentSealer{sealKeyWrapper: h.handler.connectorPayloadKey}
	h.handler.connectorPayloadKey = sealer
	issue := h.handler.issue
	signCalls := 0
	h.handler.issue = func(ctx context.Context, csr []byte, ttl time.Duration, profile crypto.LeafProfile) (crypto.IssuedLeaf, error) {
		leaf, err := issue(ctx, csr, ttl, profile)
		if err == nil {
			signCalls++
			sealer.unavailable = true
		}
		return leaf, err
	}
	box := orchestrator.NewOutbox(h.store, orchestrator.WithBackoff(func(int) time.Duration { return 0 }), orchestrator.WithMaxAttempts(2))
	var recorded store.Certificate
	originalChain := append([]byte(nil), h.handler.chainPEM...)
	for attempt := 1; attempt <= 2; attempt++ {
		if attempt == 2 {
			sealer.unavailable = false
			// Restart receiver bookkeeping and change the active chain. Recovery
			// must read durable preparation and the ORIGINAL recorded chain.
			h.handler.idem = orchestrator.NewIdempotency(h.store)
			h.handler.chainPEM = []byte("replacement active CA must not be substituted")
		}
		did, err := box.DispatchOneScoped(ctx, orchestrator.HandlerFunc(func(ctx context.Context, message orchestrator.Message) error {
			err := h.handler.Deliver(ctx, message)
			if attempt == 1 && (err == nil || !strings.Contains(err.Error(), "deployment sealing temporarily unavailable")) {
				t.Errorf("first delivery did not reach the intended post-recording failure: %v", err)
			}
			if attempt == 2 && err != nil {
				t.Errorf("recovered delivery failed: %v", err)
			}
			return err
		}), orchestrator.DestinationScope{IncludePrefixes: []string{"ca.issue"}})
		if err != nil || !did {
			t.Fatalf("dispatch %d: did=%t err=%v", attempt, did, err)
		}
		certs, err := h.store.ListCertificatesByIssuanceIdempotencyKey(ctx, h.tenant, "issue:transition:deployment-gap")
		if err != nil || len(certs) != 1 {
			t.Fatalf("attempt %d certificate count=%d err=%v", attempt, len(certs), err)
		}
		if attempt == 1 {
			recorded = certs[0]
			testRecordedFirstLeafRecoveryRefusals(t, h, ident, recorded, sealer)
		} else if !bytes.Equal(certs[0].CertificatePEM, recorded.CertificatePEM) {
			t.Fatal("recovery replaced the original public certificate chain")
		}
	}
	if signCalls != 1 {
		t.Fatalf("recovery signed %d times, want one", signCalls)
	}
	state, err := h.orch.State(ctx, h.tenant, ident.ID)
	if err != nil || state != orchestrator.StateDeployed {
		t.Fatalf("recorded certificate recovered but deployment state=%s err=%v", state, err)
	}
	deploy := pendingOutboxByDestination(t, h, "connector.deploy")
	if len(deploy.Payload) == 0 {
		t.Fatal("recovery did not queue the owed credential deployment")
	}
	payload, identityID, _, err := h.handler.resolveDeployPayload(ctx, orchestrator.Message{
		TenantID: h.tenant, Destination: deploy.Destination, IdempotencyKey: deploy.IdempotencyKey, Payload: deploy.Payload,
	})
	defer wipeConnectorDeployPayload(&payload)
	if err != nil {
		t.Fatal(err)
	}
	if identityID == nil || *identityID != ident.ID || payload.Fingerprint != recorded.Fingerprint ||
		payload.Connector != "nginx" || payload.Target != "qa-deployment-gap" ||
		!bytes.Equal(payload.CertPEM, recorded.CertificatePEM) || !bytes.Contains(payload.CertPEM, originalChain) {
		t.Fatal("recovered deployment lost original certificate, chain, or routing")
	}
	if err := crypto.VerifyCertKeyMatchPEM(payload.CertPEM, payload.KeyPEM); err != nil {
		t.Fatalf("recovered deployment key mismatch: %v", err)
	}
}

func testRecordedFirstLeafRecoveryRefusals(t *testing.T, h *issuanceDispatcherHarness, ident store.Identity, recorded store.Certificate, sealer *unavailableDeploymentSealer) {
	t.Helper()
	// A refusal must come from its own guard, not the original sealing outage.
	sealer.unavailable = false
	defer func() { sealer.unavailable = true }()
	msg := orchestrator.Message{TenantID: h.tenant, IdempotencyKey: "transition:deployment-gap"}
	ctx := withLeafCommand(t.Context(), orchestrator.NewIdempotency(h.store), h.tenant, msg.IdempotencyKey)
	p := transitionTrigger{IdentityID: ident.ID, To: string(orchestrator.StateIssued)}
	for _, scenario := range []string{"revoked", "expired", "wrong owner", "wrong command", "wrong fingerprint", "missing chain", "unretained key", "cannot unseal"} {
		t.Run(scenario, func(t *testing.T) {
			cert := recorded
			switch scenario {
			case "revoked":
				cert.Status = "revoked"
			case "expired":
				expired := time.Now().Add(-time.Minute)
				cert.NotAfter = &expired
			case "wrong owner":
				otherOwner := store.ZeroUUID
				cert.OwnerID = &otherOwner
			case "wrong fingerprint":
				cert.Fingerprint = "not-the-recorded-leaf"
			case "wrong command":
				cert.IssuanceIdempotencyKey = "issue:unrelated-command"
			case "missing chain":
				cert.CertificatePEM = nil
			case "unretained key":
				cert.KeyStorage = "locked_memory"
			case "cannot unseal":
				sealer.refuseOpen = true
				defer func() { sealer.refuseOpen = false }()
			}
			if err := h.handler.completeRecordedFirstLeaf(ctx, msg, p, cert); err == nil {
				t.Fatal("unsafe recorded certificate recovery was acknowledged")
			}
		})
	}
	for _, scenario := range []string{"missing command", "changed authority", "changed name"} {
		t.Run(scenario, func(t *testing.T) {
			lookupCtx, name := ctx, ident.Name
			selection := endpointAuthoritySelection{Source: "platform", ID: "trstctl-issuing-ca"}
			switch scenario {
			case "missing command":
				lookupCtx = withLeafCommand(ctx, h.handler.idem, h.tenant, "transition:missing-preparation")
			case "changed authority":
				selection = endpointAuthoritySelection{Source: "private", ID: "different-authority"}
			case "changed name":
				name = "different.example.test"
			}
			subject, _, err := h.handler.leafSubjectPreparation(lookupCtx, h.tenant, ident.OwnerID, name, []string{name}, selection, false)
			defer secret.Wipe(subject.KeyPEM)
			if err == nil || len(subject.KeyPEM) != 0 {
				t.Fatal("recovery generated or opened a key without its original binding")
			}
		})
	}
}

func TestFirstLeafRetryDoesNotRepeatCommittedDeployment(t *testing.T) {
	h := newIssuanceDispatcherHarness(t)
	ctx := t.Context()
	owner, err := h.orch.CreateOwner(ctx, h.tenant, "service", "committed-deployment-owner", "")
	if err != nil {
		t.Fatal(err)
	}
	ident, err := h.orch.CreateIdentity(ctx, h.tenant, store.Identity{
		Kind: store.KindX509Certificate, Name: "committed-deployment.example.test", OwnerID: owner.ID,
		Attributes: json.RawMessage(`{"connector":"nginx","target":"qa-committed-deployment"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.orch.TransitionWithIdempotency(ctx, h.tenant, ident.ID, orchestrator.StateIssued, "issue and deploy", "committed-deployment"); err != nil {
		t.Fatal(err)
	}
	issue := h.handler.issue
	signCalls := 0
	h.handler.issue = func(ctx context.Context, csr []byte, ttl time.Duration, profile crypto.LeafProfile) (crypto.IssuedLeaf, error) {
		signCalls++
		return issue(ctx, csr, ttl, profile)
	}
	lostResult := errors.New("QA: lost acknowledgement after deployment intent committed")
	h.handler.afterIssueSideEffects = func(context.Context) error { return lostResult }
	box := orchestrator.NewOutbox(h.store, orchestrator.WithBackoff(func(int) time.Duration { return 0 }), orchestrator.WithMaxAttempts(2))
	for attempt := 1; attempt <= 2; attempt++ {
		if attempt == 2 {
			h.handler.idem = orchestrator.NewIdempotency(h.store)
		}
		did, err := box.DispatchOneScoped(ctx, orchestrator.HandlerFunc(func(ctx context.Context, msg orchestrator.Message) error {
			err := h.handler.Deliver(ctx, msg)
			if attempt == 1 && !errors.Is(err, lostResult) || attempt == 2 && err != nil {
				t.Errorf("unexpected attempt %d outcome: %v", attempt, err)
			}
			return err
		}), orchestrator.DestinationScope{IncludePrefixes: []string{"ca.issue"}})
		if err != nil || !did {
			t.Fatalf("dispatch %d: did=%t err=%v", attempt, did, err)
		}
	}
	pending, err := h.outbox.Pending(ctx, h.tenant)
	if err != nil {
		t.Fatal(err)
	}
	deploys := 0
	for _, row := range pending {
		if row.Destination == "connector.deploy" {
			deploys++
		}
	}
	if deploys != 1 || signCalls != 1 {
		t.Fatalf("recovered delivery: deployments=%d signatures=%d; want one each", deploys, signCalls)
	}
}
