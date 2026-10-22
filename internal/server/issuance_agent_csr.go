// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/decommission/reprotect"
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

	var intent RelayDeployIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil {
		return nil, status.Errorf(codes.Internal, "decode renewal job payload: %v", err)
	}
	// The IP half of the binding is read from the same job payload the DNS
	// half came from; neither is taken from the request.
	if err := authorizeAgentCSRWithInspector(csrDER, permitted,
		canonicalBoundIPAddresses(intent.SubjectIPAddresses), canonicalBoundEmailAddresses(intent.SubjectEmailAddresses),
		canonicalBoundURIs(intent.SubjectURIs), d.inspectSubjectCSR); err != nil {
		return nil, err
	}
	if err := d.authorizeAgentSubjectAlgorithm(csrDER, intent.SubjectKeyAlgorithm); err != nil {
		return nil, err
	}
	identityID := strings.TrimSpace(intent.IdentityID)
	if identityID == "" {
		return nil, status.Error(codes.FailedPrecondition, "this renewal job names no identity")
	}
	ident, err := d.agentCSRIdentityUnderFence(ctx, tenantID, identityID)
	if err != nil {
		return nil, err
	}
	var hostPlan reprotect.CredentialPlan
	var hostProfileBinding *store.OperationApprovalIssuanceBinding
	if intent.ReprotectJobID != "" || intent.ReprotectPredecessorFingerprint != "" ||
		intent.ReprotectPredecessorSPKISHA256 != "" || intent.ReprotectTTLSeconds != 0 {
		hostPlan, err = reprotect.AuthorizeHostCSR(ctx, d.store, d.log, tenantID,
			job.RequiredAgentID, job.IdempotencyKey, job.Payload, csrDER, d.defaultProfile)
		if err != nil {
			return nil, status.Errorf(codes.PermissionDenied, "CA re-protection signing plan drifted: %v", err)
		}
		hostProfileBinding, err = d.caReprotectProfileBinding(ctx, tenantID, hostPlan)
		if err != nil {
			return nil, err
		}
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
	// Every production host job now retains its CSR/key in the encrypted host
	// ledger across reclaims. The signing slot must therefore be stable across
	// attempts too: a lost reply after the CA append cannot mint a second leaf
	// when the same durable job is claimed again.
	issuanceSlot := 0
	idemKey := fmt.Sprintf("agentcsr:%d:%d:%s", jobID, issuanceSlot, crypto.SHA256Hex(csrDER)[:16])

	if err := d.checkAgentCSRRequestBinding(ctx, tenantID, jobID, idemKey, intent); err != nil {
		return nil, err
	}
	out, err := d.idem.Do(ctx, tenantID, idemKey, func(ctx context.Context) ([]byte, error) {
		if err := d.authorizeAgentCSRMigrationBinding(ctx, tenantID, job.RequiredAgentID, intent); err != nil {
			return nil, err
		}
		// One durable job owns one CSR and key across claims. Transport retries
		// must preserve its serial/time/signature even if recording the result
		// fails. A different CSR is refused by the job-wide first-writer check.
		ctx = withLeafCommand(ctx, d.idem, tenantID, idemKey)
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
		var material issuedLeafMaterial
		var err error
		if intent.ReprotectJobID != "" {
			material, err = d.mintServedLeafFromCSRForReprotectAtTTL(ctx, tenantID, ident, selection,
				idemKey, csrPEM, custody.OriginHostAgent, time.Duration(hostPlan.TTLSeconds)*time.Second, hostProfileBinding)
		} else {
			material, err = d.mintServedLeafFromCSRForSelection(
				ctx, tenantID, ident, selection, idemKey, csrPEM, custody.OriginHostAgent, intent.Issuance,
			)
		}
		if err != nil {
			return nil, err
		}
		// No KeyPEM to wipe: the CSR path never produces one. That absence IS
		// the epic — every other issuance path here has a `defer
		// secret.Wipe(material.KeyPEM)` because it has key bytes to be rid of.
		return d.recordAgentCSRMaterial(ctx, tenantID, agentName, idemKey, intent, material)
	})
	if err != nil {
		return nil, agentCSRSigningError(err)
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

func (d *issuanceDispatcher) recordAgentCSRMaterial(ctx context.Context, tenantID, agentName, idemKey string,
	intent RelayDeployIntent, material issuedLeafMaterial) ([]byte, error) {
	cert := material.Certificate
	cert.IssuanceIdempotencyKey = idemKey
	// Keep the host origin recorded by the shared CSR path, and add the
	// agent identity that actually generated the subject key.
	cert.KeyOrigin = string(custody.OriginHostAgent)
	cert.KeyGeneratedBy = agentName
	if intent.ReprotectJobID != "" {
		// The predecessor remains active until the signed report proves the
		// successor is served. A certificate.recorded event with replaces_id
		// here would supersede it before the host changes one file.
		recorded, err := d.orch.RecordCertificate(ctx, tenantID, cert)
		if err != nil {
			return nil, err
		}
		usage.Record(tenantID, usage.MeterCertificatesIssued, 1)
		return marshalAgentCSRResult(recorded.Fingerprint, material)
	}
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
}

func (d *issuanceDispatcher) agentCSRIdentityUnderFence(ctx context.Context, tenantID, identityID string) (store.Identity, error) {
	if _, _, terminal, err := d.store.IdentityTerminalState(ctx, tenantID, identityID); err != nil {
		return store.Identity{}, status.Errorf(codes.Internal, "check terminal identity authority: %v", err)
	} else if terminal {
		return store.Identity{}, status.Error(codes.PermissionDenied, "the identity has terminal authority; this host job no longer authorizes signing")
	}
	ident, err := d.store.GetIdentity(ctx, tenantID, identityID)
	if err != nil {
		return store.Identity{}, status.Errorf(codes.Internal, "load identity %s: %v", identityID, err)
	}
	if ident.Status == string(orchestrator.StateRevoked) || ident.Status == string(orchestrator.StateRetired) {
		return store.Identity{}, status.Error(codes.PermissionDenied, "the identity is revoked or retired; this host job no longer authorizes signing")
	}
	return ident, nil
}

// Check the retained migration authority before the signer sees a CSR. Receipt
// validation alone is too late: a drifted job could otherwise mint an orphan
// certificate and only then fail to join the incident run.
func (d *issuanceDispatcher) authorizeAgentCSRMigrationBinding(
	ctx context.Context, tenantID, agentID string, intent RelayDeployIntent,
) error {
	if strings.TrimSpace(intent.MigrationRunID) == "" {
		return nil
	}
	record, err := d.store.GetMigrationRun(ctx, tenantID, intent.MigrationRunID)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "load migration authority: %v", err)
	}
	if record.Run.Status != migration.RunRunning && record.Run.Status != migration.RunPaused {
		return status.Error(codes.PermissionDenied, "migration is no longer issuing successors")
	}
	for _, wave := range record.Run.Waves {
		if wave.ID != intent.MigrationWaveID {
			continue
		}
		if !wave.Started || wave.Phase != migration.PhaseVerifyingLive {
			return status.Error(codes.PermissionDenied, "migration wave has not passed signed trust distribution")
		}
		member, found := migration.Member(record.Run, intent.MigrationWaveID, intent.IdentityID)
		if !found || member.TrustVerdict != migration.VerdictVerified {
			return status.Error(codes.PermissionDenied, "migration member has no signed trust verdict")
		}
		claim := migrationReceiptClaim{
			runID: intent.MigrationRunID, waveID: intent.MigrationWaveID,
			identityID: intent.IdentityID, stage: migration.StageSuccessor, renew: &intent,
		}
		if err := validateMigrationClaimBinding(member.Binding, agentID, claim); err != nil {
			return status.Errorf(codes.PermissionDenied, "migration signing authority drifted: %v", err)
		}
		return nil
	}
	return status.Error(codes.PermissionDenied, "migration renewal names no started wave")
}

// Keep retryable pending work distinct from a permanent validity refusal at
// the RPC boundary. Never infer a validity diagnosis from free-form error text.
func agentCSRSigningError(err error) error {
	if errors.Is(err, ca.ErrExternalIssuePending) || errors.Is(err, orchestrator.ErrInProgress) {
		return transport.CSRPendingError()
	}
	if crypto.IsLeafValidityViolation(err) {
		return transport.CSRValidityRefusalError()
	}
	return status.Errorf(codes.Internal, "issue against agent csr: %v", err)
}

// checkAgentCSRRequestBinding permits replay of this request's result, including
// the selected external authority's durable result, and refuses another key on
// the same durable job, including a pre-slot-0 historical claim. The caller
// holds the identity issuance fence.
func (d *issuanceDispatcher) checkAgentCSRRequestBinding(
	ctx context.Context, tenantID string, jobID int64,
	idemKey string, intent RelayDeployIntent,
) error {
	externalCAID := ""
	if strings.TrimSpace(intent.IssuingAuthoritySource) == "external" {
		externalCAID = strings.TrimSpace(intent.IssuingAuthorityID)
	}
	other, err := d.store.AgentJobSignedOtherCSR(ctx, tenantID, jobID, idemKey, externalCAID)
	if err != nil {
		return status.Errorf(codes.Internal, "check prior signature: %v", err)
	}
	if other {
		return status.Error(codes.PermissionDenied,
			"this durable host job has already had a different CSR signed; recover its retained key and result or start a new reviewed job")
	}
	return nil
}

// Call only while holding this identity's issuance fence, before replaying an
// idempotent result or making a new signing request.
func (d *issuanceDispatcher) identityStillPermitsIssuance(ctx context.Context, tenantID, identityID string) error {
	if _, _, terminal, err := d.store.IdentityTerminalState(ctx, tenantID, identityID); err != nil {
		return err
	} else if terminal {
		return errors.New("the identity has terminal authority; this command no longer authorizes issuance")
	}
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

// authorizeAgentCSRWithInspector is the authorization decision for CSR names.
//
// Split out of signAgentSubjectCSR so the decision reads as one thing rather
// than as a prologue to issuance — and because it is the part worth reading on
// its own. Everything after it is ordinary minting; everything that stops an
// agent widening its certificate is here.
func authorizeAgentCSRWithInspector(csrDER []byte, permitted, permittedIPs, permittedEmails, permittedURIs []string, inspect func([]byte) (crypto.CSRInfo, error)) error {
	// Parse before trusting anything about it. InspectCSR also verifies the
	// request's self-signature, which is what makes the CSR proof of possession
	// rather than an assertion: an agent cannot get a certificate for a public
	// key it does not hold the private half of.
	info, err := inspect(csrDER)
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
	// rfc822Name and URI SANs are compared on their own halves of the binding
	// (A35 extension): an email the binding carries matches case-insensitively,
	// a URI byte for byte, and a binding with no such half still refuses every
	// identifier of that kind. Nothing is dropped and nothing is widened.
	if offending, ok := csrIdentifiersWithinBinding(info.EmailAddresses, permittedEmails, true); !ok {
		return status.Errorf(codes.PermissionDenied,
			"this renewal job does not authorize the email address %s; a host may request a certificate for "+
				"the identifiers its binding already carries and no others", offending)
	}
	if offending, ok := csrIdentifiersWithinBinding(info.URIs, permittedURIs, false); !ok {
		return status.Errorf(codes.PermissionDenied,
			"this renewal job does not authorize the URI %s; a host may request a certificate for "+
				"the identifiers its binding already carries and no others", offending)
	}

	// IP addresses are compared on their own half of the binding, canonically
	// spelled, so 2001:db8::1 and 2001:db8:0:0::1 are one address and a DNS
	// binding with no addresses still refuses every iPAddress SAN.
	if offending, ok := csrIPAddressesWithinBinding(info.IPAddresses, permittedIPs); !ok {
		if len(permittedIPs) == 0 {
			return status.Errorf(codes.PermissionDenied,
				"this renewal job authorizes DNS names only, and the request also asserts the IP address %s; a "+
					"host may request a certificate for the names its binding carries and no others", offending)
		}
		return status.Errorf(codes.PermissionDenied,
			"this renewal job does not authorize the IP address %q; a host may request a certificate for "+
				"the addresses its binding already carries and no others", offending)
	}

	// An IP literal is never a DNS name. A dNSName SAN spelled as an address
	// would pass a string comparison against a binding that meant iPAddress,
	// and the leaf would then carry the address under a type no client
	// matches by IP — narrower than the request, and not what was authorized.
	requested := make([]string, 0, len(info.DNSNames)+1)
	for _, name := range info.DNSNames {
		if net.ParseIP(strings.TrimSpace(name)) != nil {
			return status.Errorf(codes.PermissionDenied,
				"this renewal job does not authorize %q as a DNS name; an IP address may be asserted only as an "+
					"iPAddress identifier the binding carries", name)
		}
		requested = append(requested, name)
	}
	if cn := strings.TrimSpace(info.CommonName); cn != "" {
		if ip := net.ParseIP(cn); ip != nil {
			if offending, ok := csrIPAddressesWithinBinding([]string{ip.String()}, permittedIPs); !ok {
				return status.Errorf(codes.PermissionDenied,
					"this renewal job does not authorize the common name %q; a host may request a certificate for "+
						"the addresses its binding already carries and no others", offending)
			}
		} else {
			requested = append(requested, cn)
		}
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

// csrIdentifiersWithinBinding is the subset rule for the rfc822Name and URI
// halves (A35 extension). Each requested identifier must appear in the
// binding's half: emails case-insensitively, URIs byte for byte. An empty half
// authorizes nothing of that kind, so a DNS-only binding still refuses every
// rfc822Name and URI — a binding that cannot express a claim never grants it.
func csrIdentifiersWithinBinding(requested, permitted []string, caseInsensitive bool) (string, bool) {
	if len(requested) > signJobCSRNameLimit {
		return "this request asserts more identifiers than a renewal binding may carry", false
	}
	allowed := make(map[string]bool, len(permitted))
	for _, p := range permitted {
		p = strings.TrimSpace(p)
		if caseInsensitive {
			p = strings.ToLower(p)
		}
		allowed[p] = true
	}
	for _, r := range requested {
		key := strings.TrimSpace(r)
		if caseInsensitive {
			key = strings.ToLower(key)
		}
		if key == "" || !allowed[key] {
			return fmt.Sprintf("%q", r), false
		}
	}
	return "", true
}

// csrIPAddressesWithinBinding is the subset rule for iPAddress SANs. Each
// requested address is parsed and compared canonically; an unparseable one is
// refused by its own spelling, since nothing in the binding can match it.
func csrIPAddressesWithinBinding(requested, permittedIPs []string) (string, bool) {
	if len(requested) > signJobCSRNameLimit {
		return "this request asserts more addresses than a renewal binding may carry", false
	}
	allowed := make(map[string]bool, len(permittedIPs))
	for _, ip := range permittedIPs {
		if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil {
			allowed[parsed.String()] = true
		}
	}
	for _, raw := range requested {
		parsed := net.ParseIP(strings.TrimSpace(raw))
		if parsed == nil || !allowed[parsed.String()] {
			return raw, false
		}
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
