// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/usage"
)

// Issuing against an agent-generated CSR (epic B2).
//
// The control-plane half of host-generated renewal. By the time this runs the
// agent channel has established the job and subject binding. Signing also
// rechecks the current claim and identity state while holding the same identity
// fence used by revocation, so an old job cannot outlive that authority.
//
// It deliberately reuses mintServedLeafFromCSR rather than opening a second
// issuance path. The profile gate, the CA, the certificate record and the
// custody column all behave exactly as they do for an operator-supplied CSR,
// because the ORIGIN of a CSR must not change what a certificate may assert. A
// parallel path here would be a second place for policy to drift out of sync,
// and the drift would be invisible: both paths would issue.

// signAgentSubjectCSR signs a CSR an agent generated for a renewal job it holds.
func (d *issuanceDispatcher) signAgentSubjectCSR(
	ctx context.Context, tenantID, agentName string, job store.AgentJobForRedemption,
	jobID int64, csrDER []byte, permitted []string, attempt int,
) (*transport.SignJobCSRResponse, error) {
	if d == nil || d.store == nil || d.orch == nil {
		return nil, status.Error(codes.FailedPrecondition, "issuance is not configured")
	}
	var intent RelayDeployIntent
	if json.Unmarshal(job.Payload, &intent) != nil || strings.TrimSpace(intent.IdentityID) == "" {
		return nil, status.Error(codes.FailedPrecondition, "renewal job has no identity binding")
	}
	var response *transport.SignJobCSRResponse
	err := d.store.WithIdentityIssuanceFence(ctx, tenantID, intent.IdentityID, func(fenced context.Context) error {
		checkClaim := func() error {
			current, held, err := d.store.GetAgentJobForRedemption(fenced, tenantID, agentRowID(tenantID, agentName), jobID, time.Now().UTC())
			if err != nil {
				return err
			}
			if !held || current.ClaimAttempts != attempt || current.Destination != job.Destination || current.IdempotencyKey != job.IdempotencyKey || !bytes.Equal(current.Payload, job.Payload) {
				return status.Error(codes.PermissionDenied, "this agent no longer holds the exact issuance job")
			}
			return nil
		}
		if err := checkClaim(); err != nil {
			return err
		}
		var err error
		response, err = d.signAgentSubjectCSRUnderFence(fenced, tenantID, agentName, job, jobID, csrDER, permitted, attempt)
		if err != nil {
			return err
		}
		return checkClaim()
	})
	if errors.Is(err, store.ErrIdentityIssuanceBusy) {
		// A previous call or lifecycle decision still holds this identity's
		// fence. Preserve the request until it finishes, then recheck authority.
		return nil, transport.CSRPendingError()
	}
	if err != nil {
		return nil, err
	}
	return response, nil
}

func (d *issuanceDispatcher) signAgentSubjectCSRUnderFence(
	ctx context.Context,
	tenantID, agentName string,
	job store.AgentJobForRedemption,
	jobID int64,
	csrDER []byte,
	permitted []string,
	attempt int,
) (*transport.SignJobCSRResponse, error) {
	if d == nil || d.store == nil || d.orch == nil {
		return nil, status.Error(codes.FailedPrecondition, "issuance is not configured")
	}

	if err := authorizeAgentCSR(csrDER, permitted); err != nil {
		return nil, err
	}

	var intent RelayDeployIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil {
		return nil, status.Errorf(codes.Internal, "decode renewal job payload: %v", err)
	}
	identityID := strings.TrimSpace(intent.IdentityID)
	if identityID == "" {
		return nil, status.Error(codes.FailedPrecondition, "this renewal job names no identity")
	}
	ident, err := d.store.GetIdentity(ctx, tenantID, identityID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load identity %s: %v", identityID, err)
	}
	if ident.Status == string(orchestrator.StateRevoked) || ident.Status == string(orchestrator.StateRetired) {
		return nil, status.Error(codes.PermissionDenied, "the identity is revoked or retired; this host job no longer authorizes signing")
	}

	// Idempotency keyed on the CSR'S OWN BYTES, not on the job attempt alone.
	//
	// A retry after a timeout must return the SAME certificate — the agent holds
	// exactly one key and a second certificate for a second key it discarded is
	// an orphan the estate will never serve. But an agent that genuinely
	// regenerated its key needs a genuinely new certificate, and returning the
	// first one would hand it a certificate whose private half no longer exists
	// anywhere. Hashing the request distinguishes the two cases without asking
	// the agent to tell us which it is.
	// Through the internal/crypto boundary (AN-3), not crypto/sha256 directly.
	// The rule holds even for a digest that is only ever an idempotency key:
	// a boundary with exceptions for "harmless" uses stops being checkable.
	// The ATTEMPT is in the key, so the single-use check can scope to it: one
	// signature per claim, but a genuine re-claim may sign again.
	idemKey := fmt.Sprintf("agentcsr:%d:%d:%s", jobID, attempt, crypto.SHA256Hex(csrDER)[:16])

	if err := d.checkAgentCSRRequestBinding(ctx, tenantID, jobID, attempt, idemKey, intent); err != nil {
		return nil, err
	}

	out, err := d.idem.Do(ctx, tenantID, idemKey, func(ctx context.Context) ([]byte, error) {
		csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
		selection := endpointAuthoritySelection{
			Source: strings.TrimSpace(intent.IssuingAuthoritySource),
			ID:     strings.TrimSpace(intent.IssuingAuthorityID),
		}
		if selection.Source == "" {
			// Migration jobs predate the source field and always pin a private
			// signer-backed hierarchy authority. An empty ID is the legacy
			// platform issuer; neither case guesses an external CA.
			selection = endpointAuthoritySelection{Source: "platform", ID: "trstctl-issuing-ca"}
			if strings.TrimSpace(intent.IssuingAuthorityID) != "" {
				selection = endpointAuthoritySelection{Source: "private", ID: strings.TrimSpace(intent.IssuingAuthorityID)}
			}
		}
		material, err := d.mintServedLeafFromCSRForSelection(
			ctx, tenantID, ident, selection, idemKey, csrPEM, intent.Issuance,
		)
		if err != nil {
			return nil, err
		}
		// No KeyPEM to wipe: the CSR path never produces one. That absence IS
		// the epic — every other issuance path here has a `defer
		// secret.Wipe(material.KeyPEM)` because it has key bytes to be rid of.
		cert := material.Certificate
		cert.IssuanceIdempotencyKey = idemKey
		// The narrower custody claim, and a true one (B5's vocabulary). The
		// shared CSR path records "requester", which is correct but weaker: it
		// says the control plane did not generate the key. Here we know more —
		// a trstctl agent generated it on the host that will serve it — and
		// recording the weaker fact when the stronger one is known is exactly
		// the kind of understatement that makes a custody column useless for
		// deciding which credentials still need migrating.
		cert.KeyOrigin = string(custody.OriginHostAgent)
		cert.KeyGeneratedBy = agentName
		if predecessor := strings.TrimSpace(intent.PredecessorCertificateID); predecessor != "" {
			// RecordSuccessorCertificate, not RecordCertificate. The difference
			// is ReplacesID, and without it the projector never runs the
			// `SET status='superseded'` update — leaving the identity with two
			// certificates reading active, which inflates expiry alerts, fleet
			// counts and D3's three-state view all at once.
			recorded, err := d.orch.RecordSuccessorCertificate(ctx, tenantID, cert, predecessor)
			if err != nil {
				return nil, err
			}
			usage.Record(tenantID, usage.MeterCertificatesIssued, 1)
			return marshalAgentCSRResult(recorded.Fingerprint, material)
		}
		recorded, err := d.orch.RecordCertificate(ctx, tenantID, cert)
		if err != nil {
			return nil, err
		}
		usage.Record(tenantID, usage.MeterCertificatesIssued, 1)
		return marshalAgentCSRResult(recorded.Fingerprint, material)
	})
	if errors.Is(err, ca.ErrExternalIssuePending) || errors.Is(err, orchestrator.ErrInProgress) {
		return nil, transport.CSRPendingError()
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "issue against agent csr: %v", err)
	}

	fingerprint, certPEM, chainPEM, ok := splitAgentCSRResult(out)
	if !ok {
		return nil, status.Error(codes.Internal, "issued certificate could not be read back")
	}
	if err := d.bindAgentCSRMigrationSuccessor(ctx, tenantID, job.IdempotencyKey, intent, fingerprint); err != nil {
		return nil, err
	}
	if len(chainPEM) == 0 {
		chainPEM = d.chainPEM
	}
	return &transport.SignJobCSRResponse{
		CertificatePEM: certPEM,
		ChainPEM:       append([]byte(nil), chainPEM...),
		Fingerprint:    fingerprint,
	}, nil
}

// checkAgentCSRRequestBinding permits replay of this request's result, including
// the selected external authority's durable result, and refuses another key on
// the same claim. The caller holds the identity issuance fence.
func (d *issuanceDispatcher) checkAgentCSRRequestBinding(
	ctx context.Context, tenantID string, jobID int64, attempt int,
	idemKey string, intent RelayDeployIntent,
) error {
	externalCAID := ""
	if strings.TrimSpace(intent.IssuingAuthoritySource) == "external" {
		externalCAID = strings.TrimSpace(intent.IssuingAuthorityID)
	}
	other, err := d.store.AgentJobAttemptSignedOtherCSR(ctx, tenantID, jobID, attempt, idemKey, externalCAID)
	if err != nil {
		return status.Errorf(codes.Internal, "check prior signature: %v", err)
	}
	if other {
		return status.Error(codes.PermissionDenied,
			"this attempt has already had a different request signed; re-claim the job to "+
				"certify a new key")
	}
	return nil
}

// Call only while holding this identity's issuance fence, before replaying an
// idempotent result or making a new signing request.
func (d *issuanceDispatcher) identityStillPermitsIssuance(ctx context.Context, tenantID, identityID string) error {
	ident, err := d.store.GetIdentity(ctx, tenantID, identityID)
	if err != nil {
		return err
	}
	if ident.Status == string(orchestrator.StateRevoked) || ident.Status == string(orchestrator.StateRetired) {
		return errors.New("the identity is revoked or retired; this command no longer authorizes issuance")
	}
	return nil
}

func (d *issuanceDispatcher) bindAgentCSRMigrationSuccessor(
	ctx context.Context,
	tenantID, jobIdempotencyKey string,
	intent RelayDeployIntent,
	fingerprint string,
) error {
	if strings.TrimSpace(intent.MigrationRunID) == "" {
		return nil
	}
	eventID := orchestrator.MigrationEventID(tenantID, intent.MigrationRunID, "issued:"+jobIdempotencyKey)
	_, err := d.orch.UpdateMigrationRun(ctx, tenantID, intent.MigrationRunID, eventID,
		func(current migration.Run) (migration.Run, []migration.Action, error) {
			member, found := migration.Member(current, intent.MigrationWaveID, intent.IdentityID)
			if !found {
				return current, nil, fmt.Errorf("server: migration CSR job names no current run member")
			}
			claim := migrationReceiptClaim{
				runID: intent.MigrationRunID, waveID: intent.MigrationWaveID,
				identityID: intent.IdentityID, stage: migration.StageSuccessor, renew: &intent,
			}
			if err := validateMigrationClaimBinding(member.Binding, intent.RequiredAgentID, claim); err != nil {
				return current, nil, err
			}
			next, err := migration.RecordSuccessorIssued(
				current, intent.MigrationWaveID, intent.IdentityID, fingerprint,
			)
			return next, nil, err
		})
	if err != nil {
		return status.Errorf(codes.Internal, "bind issued successor to migration: %v", err)
	}
	return nil
}

// authorizeAgentCSR is the whole authorization decision for an agent's request.
//
// Split out of signAgentSubjectCSR so the decision reads as one thing rather
// than as a prologue to issuance — and because it is the part worth reading on
// its own. Everything after it is ordinary minting; everything that stops an
// agent widening its certificate is here.
func authorizeAgentCSR(csrDER []byte, permitted []string) error {
	// Parse before trusting anything about it. InspectCSR also verifies the
	// request's self-signature, which is what makes the CSR proof of possession
	// rather than an assertion: an agent cannot get a certificate for a public
	// key it does not hold the private half of.
	info, err := crypto.InspectCSR(csrDER)
	if err != nil {
		return status.Errorf(codes.InvalidArgument,
			"csr is not a valid, self-signed PKCS#10 request: %v", err)
	}

	// EVERY identifier the leaf will carry has to be checked, not just the DNS
	// ones — and the set that matters is decided by the SIGNER, not by this
	// function. crypto.SignLeafFromCSRWithProfile copies csr.Subject,
	// csr.DNSNames, csr.IPAddresses, csr.EmailAddresses and csr.URIs verbatim
	// into the certificate. A check that read only DNSNames and the CommonName
	// left four of those unguarded: an agent holding a legitimate renewal for
	// api.example.test could add an iPAddress SAN, or a spiffe:// URI, or an
	// rfc822Name, and the control plane would sign every one of them.
	//
	// A renewal binding names DNS hosts and nothing else, so it can authorize
	// nothing else. The other SAN types are therefore REFUSED outright rather
	// than compared: there is no value of the binding that could permit them,
	// and silently dropping them would issue a certificate that does not match
	// the request the agent proved possession of.
	if offending, ok := csrCarriesOnlyDNSIdentifiers(info); !ok {
		return status.Errorf(codes.PermissionDenied,
			"this renewal job authorizes DNS names only, and the request also asserts %s; a "+
				"host may request a certificate for the names its binding carries and no others",
			offending)
	}

	requested := append([]string(nil), info.DNSNames...)
	if cn := strings.TrimSpace(info.CommonName); cn != "" {
		requested = append(requested, cn)
	}
	if offending, ok := csrNamesWithinBinding(requested, permitted); !ok {
		// Named in the error on purpose. This is the one refusal an operator
		// debugging a renewal needs to be able to act on, and "denied" without
		// the name sends them to read agent logs to find out which SAN was the
		// problem. The name came from the tenant's own request, so echoing it
		// discloses nothing they did not send.
		return status.Errorf(codes.PermissionDenied,
			"this renewal job does not authorize the name %q; a host may request a certificate for "+
				"the names its binding already carries and no others", offending)
	}
	return nil
}

// csrCarriesOnlyDNSIdentifiers refuses a renewal CSR asserting anything a DNS
// binding cannot authorize.
//
// Named separately from the subset rule because it answers a different question.
// The subset rule asks "is this name one the job carries"; this asks "is this
// even a KIND of identifier the job could carry". A binding built from
// SubjectDNSNames has no way to express an IP address or a URI, so a request
// containing one is outside the vocabulary of the authorization entirely — and
// an authorization that cannot express a claim must never be read as granting it.
func csrCarriesOnlyDNSIdentifiers(info crypto.CSRInfo) (string, bool) {
	switch {
	case len(info.IPAddresses) > 0:
		return fmt.Sprintf("the IP address %s", info.IPAddresses[0]), false
	case len(info.EmailAddresses) > 0:
		return fmt.Sprintf("the email address %s", info.EmailAddresses[0]), false
	case len(info.URIs) > 0:
		return fmt.Sprintf("the URI %s", info.URIs[0]), false
	}
	return "", true
}

type storedAgentCSRResult struct {
	Fingerprint    string `json:"fingerprint"`
	CertificatePEM []byte `json:"certificate_pem"`
	ChainPEM       []byte `json:"chain_pem,omitempty"`
}

func marshalAgentCSRResult(fingerprint string, material issuedLeafMaterial) ([]byte, error) {
	return json.Marshal(storedAgentCSRResult{
		Fingerprint: fingerprint, CertificatePEM: material.CertPEM, ChainPEM: material.ChainPEM,
	})
}

// splitAgentCSRResult decodes the structured JSON result and retains support for
// the old fingerprint-newline-certificate form already present in durable
// idempotency rows during a rolling upgrade.
//
// The idempotent runner stores one byte slice, and a replayed call must return
// the certificate as well as the fingerprint — an agent that got only a
// fingerprint back on retry would have nothing to install.
func splitAgentCSRResult(raw []byte) (string, []byte, []byte, bool) {
	var stored storedAgentCSRResult
	if json.Unmarshal(raw, &stored) == nil && strings.TrimSpace(stored.Fingerprint) != "" && len(stored.CertificatePEM) > 0 {
		return stored.Fingerprint, append([]byte(nil), stored.CertificatePEM...), append([]byte(nil), stored.ChainPEM...), true
	}
	idx := -1
	for i, b := range raw {
		if b == '\n' {
			idx = i
			break
		}
	}
	if idx <= 0 || idx+1 >= len(raw) {
		return "", nil, nil, false
	}
	return string(raw[:idx]), append([]byte(nil), raw[idx+1:]...), nil, true
}

// signAgentSubjectCSR is the Server-level seam the agent channel is wired to.
//
// It exists so the agent service holds a function rather than the dispatcher
// itself: the channel is assembled before the dispatcher is known to be
// serving, and a nil dispatcher must produce a clean "not configured" refusal
// rather than a panic on the first renewal an agent attempts.
func (s *Server) signAgentSubjectCSR(
	ctx context.Context,
	tenantID, agentName string,
	job store.AgentJobForRedemption,
	jobID int64,
	csrDER []byte,
	permitted []string,
	attempt int,
) (*transport.SignJobCSRResponse, error) {
	d, ok := s.obHandler.(*issuanceDispatcher)
	if !ok || d == nil || (d.issue == nil && d.authorityIssue == nil) {
		return nil, status.Error(codes.FailedPrecondition,
			"this control plane has no issuing CA, so it cannot sign a host-generated request")
	}
	return d.signAgentSubjectCSR(ctx, tenantID, agentName, job, jobID, csrDER, permitted, attempt)
}
