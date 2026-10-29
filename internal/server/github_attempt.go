// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

type githubAttemptPreparation struct {
	Leaf       crypto.LeafPreparation `json:"leaf"`
	VerifiedAt time.Time              `json:"verified_at"`
}

// Opaque issuance recovery bytes contain only operational coordinates. Subject,
// owner, repository and arbitrary claims stay in the privacy-managed attestation
// events; copying them here would bypass their field-level erasure rules.
type githubAttemptEvidence struct {
	RunID      string    `json:"run_id"`
	RunAttempt string    `json:"run_attempt"`
	VerifiedAt time.Time `json:"verified_at"`
}

func githubAttemptCertificateEventID(key string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("github-attempt-certificate-v1\x00"+key)).String()
}

// The identity comes only from verified claims. Neither an HTTP key nor the
// runner's environment, job or action can allocate another slot in this attempt.
func githubAttemptKey(tenantID string, att attest.Attestation) (string, error) {
	tenant, err := uuid.Parse(tenantID)
	if err != nil || tenant == uuid.Nil {
		return "", api.ErrAttestedIssuanceInvalid
	}
	for _, name := range []string{"run_id", "run_attempt"} {
		value := att.Claims[name]
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != value {
			return "", fmt.Errorf("%w: canonical signed %s is required", api.ErrAttestedIssuanceRejected, name)
		}
	}
	issuer, repository := att.Claims["fulcio_issuer"], att.Claims["repository"]
	if issuer == "" || repository == "" {
		return "", fmt.Errorf("%w: signed GitHub issuer and repository are required", api.ErrAttestedIssuanceRejected)
	}
	wire, err := json.Marshal([]string{"github-attempt-v1", tenant.String(), issuer, strings.ToLower(repository), att.Claims["run_id"], att.Claims["run_attempt"]})
	if err != nil {
		return "", err
	}
	return "attested-github-attempt:v1:" + crypto.SHA256Hex(wire), nil
}

func (s *attestedIssuerService) issueGitHubAttempt(ctx context.Context, tenantID string, verifier *attest.Verifier, att attest.Attestation, publicKey []byte, ttl time.Duration) (api.AttestedSVID, error) {
	key, err := githubAttemptKey(tenantID, att)
	if err != nil {
		return api.AttestedSVID{}, err
	}
	// PostgreSQL UUIDs and the attempt key use one spelling. Use that same
	// tenant in the retained envelope and SPIFFE namespace, including direct
	// service callers that supplied an equivalent uppercase UUID.
	tenant, _ := uuid.Parse(tenantID) // githubAttemptKey already validated it.
	tenantID = tenant.String()
	spiffeID, err := attestedSPIFFEID(s.trustDomain, tenantID, att.Method, att.Subject)
	if err != nil {
		return api.AttestedSVID{}, fmt.Errorf("%w: %v", api.ErrAttestedIssuanceInvalid, err)
	}
	if err := crypto.RefuseWeakSubjectKey(publicKey); err != nil {
		return api.AttestedSVID{}, fmt.Errorf("%w: invalid workload public key", api.ErrAttestedIssuanceInvalid)
	}
	if err := refuseCompromisedPublicKey(ctx, s.store, tenantID, publicKey); err != nil {
		return api.AttestedSVID{}, err
	}
	// Exclude JWT timestamps/signature and the caller's key: a fresh valid proof
	// may recover an identical command. Include all verified identity attributes,
	// the exact issuer, public key, SPIFFE identity and effective lifetime.
	wire, err := json.Marshal(struct {
		Issuer, PublicKey       []byte
		CAID, SPIFFEID, Subject string
		Claims                  map[string]string
		Selectors               []string
		TTL                     time.Duration
	}{s.caCertDER, publicKey, s.caID, spiffeID, att.Subject, att.Claims, att.Selectors, ttl})
	if err != nil {
		return api.AttestedSVID{}, err
	}
	binding := crypto.SHA256Hex(wire)
	recovered, err := recoverCertificatesByIssuanceKey(ctx, s.store, s.log, tenantID, key)
	if err != nil {
		return api.AttestedSVID{}, err
	}
	if len(recovered) > 0 {
		if len(recovered) != 1 {
			return api.AttestedSVID{}, errors.New("server: GitHub attempt has multiple retained certificates")
		}
		return s.recoverGitHubAttempt(ctx, tenantID, verifier, att, recovered[0], binding, ttl)
	}
	journal, ok := s.caSigner.(journaledLeafSigner)
	if !ok || s.idem == nil {
		return api.AttestedSVID{}, errors.New("server: GitHub attempt requires durable template and signer result storage")
	}
	// This is the existing receiver-bookkeeping protocol, also used by lifecycle
	// issuance. It commits the public template before any signing operation. The
	// independent signer journal refuses a changed digest even if bookkeeping is
	// lost; restoring the original preparation is then required, never a remint.
	preparedJSON, err := s.idem.DoBound(ctx, tenantID, "github-attempt-template:v1:"+key, binding, func(context.Context) ([]byte, error) {
		leaf, err := crypto.NewLeafPreparation()
		if err != nil {
			return nil, err
		}
		return json.Marshal(githubAttemptPreparation{Leaf: leaf, VerifiedAt: att.VerifiedAt})
	})
	if err != nil {
		return api.AttestedSVID{}, err
	}
	var prepared githubAttemptPreparation
	if err := json.Unmarshal(preparedJSON, &prepared); err != nil || prepared.VerifiedAt.IsZero() {
		return api.AttestedSVID{}, errors.New("server: invalid retained GitHub attempt preparation")
	}
	certDER, err := crypto.SignSVIDWithPreparation(s.caCertDER, leafOperationSigner{journal, key}, publicKey, spiffeID, ttl, prepared.Leaf)
	if err != nil {
		return api.AttestedSVID{}, fmt.Errorf("server: sign GitHub attempt SVID: %w", err)
	}
	info, err := certinfo.Inspect(certDER)
	if err != nil {
		return api.AttestedSVID{}, err
	}
	att.VerifiedAt = prepared.VerifiedAt
	response, err := json.Marshal(githubAttemptEvidence{RunID: att.Claims["run_id"], RunAttempt: att.Claims["run_attempt"], VerifiedAt: prepared.VerifiedAt})
	if err != nil {
		return api.AttestedSVID{}, err
	}
	nb, na := info.NotBefore, info.NotAfter
	sans := sansOf(info)
	if sans == nil {
		sans = []string{}
	}
	// This receiver accepts the complete public issuance fact, including the
	// retained response. Its first-writer event identity is the signed attempt,
	// independent of the certificate fingerprint or HTTP idempotency key.
	payload, err := json.Marshal(projections.CertificateRecorded{
		ID:   uuid.NewSHA1(uuid.NameSpaceOID, []byte("github-attempt-row-v1\x00"+key)).String(),
		CAID: s.caID, Subject: info.Subject, SANs: sans, Issuer: info.Issuer,
		Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
		KeyAlgorithm: info.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
		Source: "attested:github_oidc", CertificateDER: append([]byte(nil), certDER...),
		IssuanceIdempotencyKey: key, IssuanceRequestBinding: binding, IssuanceResponse: response,
		KeyOrigin: string(custody.OriginRequester),
	})
	if err != nil {
		return api.AttestedSVID{}, err
	}
	if err := s.orch.RecordCertificateEvent(ctx, events.Event{ID: githubAttemptCertificateEventID(key), Type: projections.EventCertificateRecorded, TenantID: tenantID, Data: payload}); err != nil {
		return api.AttestedSVID{}, err
	}
	return s.finish(ctx, tenantID, verifier, att, certDER, ttl, true)
}

// A mutable inventory row cannot invent a completed attempt. Check the retained
// certificate event before recovering its original attempt evidence. Identity
// claims are verified afresh and must still match the original request binding.
func (s *attestedIssuerService) recoverGitHubAttempt(ctx context.Context, tenantID string, verifier *attest.Verifier, att attest.Attestation, row store.Certificate, binding string, ttl time.Duration) (api.AttestedSVID, error) {
	event, found, err := s.log.EventByID(ctx, githubAttemptCertificateEventID(row.IssuanceIdempotencyKey))
	if err != nil {
		return api.AttestedSVID{}, err
	}
	if !found {
		return api.AttestedSVID{}, errors.New("server: GitHub attempt certificate has no retained issuance event")
	}
	var retained projections.CertificateRecorded
	if event.Type != projections.EventCertificateRecorded || event.TenantID != tenantID || projections.ValidateSchemaVersion(event) != nil ||
		json.Unmarshal(event.Data, &retained) != nil || retained.IssuanceIdempotencyKey != row.IssuanceIdempotencyKey ||
		retained.Fingerprint != row.Fingerprint || retained.IssuanceRequestBinding != row.IssuanceRequestBinding ||
		!bytes.Equal(retained.CertificateDER, row.CertificateDER) {
		return api.AttestedSVID{}, errors.New("server: GitHub attempt inventory differs from retained issuance")
	}
	if retained.IssuanceRequestBinding != binding {
		return api.AttestedSVID{}, fmt.Errorf("%w: GitHub attempt already belongs to a different public key or command", orchestrator.ErrIdempotencyConflict)
	}
	var evidence githubAttemptEvidence
	if err := json.Unmarshal(retained.IssuanceResponse, &evidence); err != nil || evidence.VerifiedAt.IsZero() ||
		evidence.RunID != att.Claims["run_id"] || evidence.RunAttempt != att.Claims["run_attempt"] {
		return api.AttestedSVID{}, errors.New("server: retained GitHub attempt response is invalid")
	}
	att.VerifiedAt = evidence.VerifiedAt
	return s.finish(ctx, tenantID, verifier, att, retained.CertificateDER, ttl, false)
}
