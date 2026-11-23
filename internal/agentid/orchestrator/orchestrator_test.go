// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	agidapi "trstctl.com/trstctl/internal/agentid/api"
	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/agentid/revoke"
	coreorch "trstctl.com/trstctl/internal/orchestrator"
)

type cr053Revocations struct {
	subject string
	seen    []string
	err     error
}

func (r *cr053Revocations) IsRevoked(string, []byte) (bool, error)    { return false, r.err }
func (r *cr053Revocations) IsKeyRevoked(string, []byte) (bool, error) { return false, r.err }
func (r *cr053Revocations) IsSubjectRevoked(_ string, subject string) (bool, error) {
	r.seen = append(r.seen, subject)
	return subject == r.subject, r.err
}

func TestCR053IssuanceRetryChecksEverySubjectAndChainlessAgent(t *testing.T) {
	chain := delegation.PreconditionsBody{Chain: []delegation.RecordEnvelope{
		{Record: delegation.Record{TenantID: "tenant-a", DelegatorID: "root", DelegateID: "middle"}},
		{Record: delegation.Record{TenantID: "tenant-a", DelegatorID: "middle", DelegateID: "leaf"}},
	}}
	for _, subject := range []string{"root", "middle", "leaf", "agent"} {
		t.Run(subject, func(t *testing.T) {
			reader := &cr053Revocations{subject: subject}
			body := chain
			if subject == "agent" {
				body = delegation.PreconditionsBody{}
			}
			err := checkRevocation(reader, "tenant-a", "agent", body)
			if err == nil || !strings.Contains(err.Error(), "revocation directive") {
				t.Fatalf("revoked %s was not refused: %v", subject, err)
			}
		})
	}
	reader := &cr053Revocations{err: errors.New("projection unavailable")}
	if err := checkRevocation(reader, "tenant-a", "agent", chain); !errors.Is(err, reader.err) {
		t.Fatalf("unavailable projection must fail closed: %v", err)
	}
}

// TestDestinations_MatchAPI asserts the worker drains exactly the destinations the API
// enqueues, and the cascade job destinations it re-exports. A drift would silently break a
// journey (an enqueued message no handler drains).
func TestDestinations_MatchAPI(t *testing.T) {
	if IssuanceRequestDestination != agidapi.IssuanceRequestDestination {
		t.Errorf("IssuanceRequestDestination %q != API %q", IssuanceRequestDestination, agidapi.IssuanceRequestDestination)
	}
	if RevocationDirectiveDestination != agidapi.RevocationDirectiveDestination {
		t.Errorf("RevocationDirectiveDestination %q != API %q", RevocationDirectiveDestination, agidapi.RevocationDirectiveDestination)
	}
	if RevocationJobDestination != revoke.DestinationRevocationJob {
		t.Errorf("RevocationJobDestination %q != revoke %q", RevocationJobDestination, revoke.DestinationRevocationJob)
	}
	if DownstreamPlaneDestination != revoke.DestinationDownstreamPlane {
		t.Errorf("DownstreamPlaneDestination %q != revoke %q", DownstreamPlaneDestination, revoke.DestinationDownstreamPlane)
	}
}

// TestDeliverLicensed_UnknownPassThrough asserts the composed handler returns handled=false
// (no error) for a non-AGID destination, so the chained handler in cmd/trstctl can try the
// next edition's handler. This path does not touch the workers, so it needs no substrate.
func TestDeliverLicensed_UnknownPassThrough(t *testing.T) {
	h := &handler{}
	handled, err := h.DeliverLicensed(context.Background(), coreorch.Message{Destination: "some.other.feature.job"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handled {
		t.Fatalf("handled = true for a non-AGID destination, want false (pass-through)")
	}
}

// TestDeliverLicensed_DownstreamAck asserts the downstream-plane destination is a
// successful ack (handled=true, nil error) so the outbox row marks delivered — the
// downstream trust plane consumes the KRL/CRL entry, mirroring PCAS's pcas.rp-publish ack.
func TestDeliverLicensed_DownstreamAck(t *testing.T) {
	h := &handler{}
	handled, err := h.DeliverLicensed(context.Background(), coreorch.Message{Destination: DownstreamPlaneDestination})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !handled {
		t.Fatalf("handled = false for the downstream-plane ack, want true")
	}
}

func TestReachabilitySubjectDigestMatchesSignerAuthorityDigest(t *testing.T) {
	auth := delegation.Authority{
		Scopes: []string{"read"},
		Tools:  []string{"search"},
		Spend:  delegation.Budget{Amount: 10, Currency: "usd"},
		Rate:   delegation.Rate{Limit: 5, Per: "minute"},
		Depth:  1,
	}
	body := delegation.PreconditionsBody{Chain: []delegation.RecordEnvelope{{Record: delegation.Record{Authority: auth}}}}
	got := headAuthorityDigest(body, nil)
	want, err := delegation.CanonicalDigest(auth, nil)
	if err != nil {
		t.Fatalf("CanonicalDigest: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("reachability subject digest must be the final authority digest the signer verifies")
	}
}

func TestRevocationHeadDigestUsesRecordDigest(t *testing.T) {
	auth := delegation.Authority{Scopes: []string{"read"}, Depth: 1}
	rec := delegation.Record{TenantID: "t1", DelegatorID: "root", DelegateID: "leaf", Authority: auth, RootAnchor: true}
	body := delegation.PreconditionsBody{Chain: []delegation.RecordEnvelope{{Record: rec}}}
	got := headRecordDigest(body, nil)
	want, err := rec.Digest(nil)
	if err != nil {
		t.Fatalf("record digest: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("revocation pre-check must use the final delegation record digest")
	}
}

// TestDeliverLicensed_AttestationBindingAck asserts the attestation-binding publish
// intent — enqueued by the brokerstore recorder in the SAME transaction as every
// chain-bound issuance — is OWNED by this worker (handled=true, nil error) so the
// outbox row marks delivered. Before this case existed the row was undeliverable:
// it fell through internal/server's dispatcher to "unsupported first-party outbox
// destination", burned all ten attempts, and dead-lettered on every issuance (AUD-5).
func TestDeliverLicensed_AttestationBindingAck(t *testing.T) {
	h := &handler{}
	handled, err := h.DeliverLicensed(context.Background(), coreorch.Message{
		Destination: delegation.AttestationBindingDestination,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !handled {
		t.Fatal("handled = false for agid.attestation.bound — the recorder enqueues this destination on every chain-bound issuance and it MUST be owned (AUD-5)")
	}
	if AttestationBindingDestination != delegation.AttestationBindingDestination {
		t.Errorf("AttestationBindingDestination %q != delegation %q", AttestationBindingDestination, delegation.AttestationBindingDestination)
	}
}
