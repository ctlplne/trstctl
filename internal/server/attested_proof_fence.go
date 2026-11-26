// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

type attestedProofPreparation struct {
	Leaf       crypto.LeafPreparation `json:"leaf"`
	VerifiedAt time.Time              `json:"verified_at"`
}

type attestedProofEvidence struct {
	VerifiedAt time.Time `json:"verified_at"`
}

// A token can be refreshed, so one signed token gets one leaf. AWS and Azure
// instance documents have no expiry or fresh nonce; each instance gets only one
// leaf for its lifetime. The current TPM envelope also has no server challenge,
// so one AK gets one leaf until its challenge protocol is replaced. Neither the
// HTTP retry key nor a changed public key can allocate another slot.
func attestedProofKey(tenantID string, att attest.Attestation, proof []byte) (string, error) {
	tenant, err := uuid.Parse(tenantID)
	if err != nil || tenant == uuid.Nil || len(proof) == 0 || att.Subject == "" {
		return "", api.ErrAttestedIssuanceInvalid
	}
	proofIdentity := crypto.SHA256Hex(proof)
	if att.Method == "aws_iid" || att.Method == "azure_imds" || att.Method == "tpm" {
		proofIdentity = att.Subject
	}
	wire, err := json.Marshal([]string{"attested-proof-v1", tenant.String(), att.Method, att.Subject, proofIdentity})
	if err != nil {
		return "", err
	}
	return "attested-proof:v1:" + crypto.SHA256Hex(wire), nil
}

func attestedProofEventID(key string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("attested-proof-certificate-v1\x00"+key)).String()
}

func (s *attestedIssuerService) attestedProofBinding(att attest.Attestation, publicKey []byte, spiffeID string, ttl time.Duration) (string, error) {
	wire, err := json.Marshal(struct {
		Issuer, PublicKey       []byte
		CAID, SPIFFEID, Subject string
		Claims                  map[string]string
		Selectors               []string
		TTL                     time.Duration
	}{s.caCertDER, publicKey, s.caID, spiffeID, att.Subject, att.Claims, att.Selectors, ttl})
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(wire), nil
}

func (s *attestedIssuerService) issueFencedAttestation(ctx context.Context, tenantID string, verifier *attest.Verifier, att attest.Attestation, proof, publicKey []byte, ttl time.Duration) (api.AttestedSVID, error) {
	key, err := attestedProofKey(tenantID, att, proof)
	if err != nil {
		return api.AttestedSVID{}, err
	}
	tenant, _ := uuid.Parse(tenantID)
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
	binding, err := s.attestedProofBinding(att, publicKey, spiffeID, ttl)
	if err != nil {
		return api.AttestedSVID{}, err
	}
	recovered, err := recoverCertificatesByIssuanceKey(ctx, s.store, s.log, tenantID, key)
	if err != nil {
		return api.AttestedSVID{}, err
	}
	if len(recovered) != 0 {
		if len(recovered) != 1 {
			return api.AttestedSVID{}, errors.New("server: attested proof has multiple retained certificates")
		}
		return s.recoverAttestedProof(ctx, tenantID, verifier, att, recovered[0], binding, ttl)
	}
	journal, ok := s.caSigner.(journaledLeafSigner)
	if !ok || s.idem == nil {
		return api.AttestedSVID{}, errors.New("server: attested proof requires durable template and signer result storage")
	}
	preparedJSON, err := s.idem.DoBound(ctx, tenantID, "attested-proof-template:v1:"+key, binding, func(context.Context) ([]byte, error) {
		leaf, err := crypto.NewLeafPreparation()
		if err != nil {
			return nil, err
		}
		return json.Marshal(attestedProofPreparation{Leaf: leaf, VerifiedAt: att.VerifiedAt})
	})
	if err != nil {
		return api.AttestedSVID{}, err
	}
	var prepared attestedProofPreparation
	if err := json.Unmarshal(preparedJSON, &prepared); err != nil || prepared.VerifiedAt.IsZero() {
		return api.AttestedSVID{}, errors.New("server: invalid retained attested proof preparation")
	}
	certDER, err := crypto.SignSVIDWithPreparation(s.caCertDER, leafOperationSigner{journal, key}, publicKey, spiffeID, ttl, prepared.Leaf)
	if err != nil {
		return api.AttestedSVID{}, fmt.Errorf("server: sign attested SVID: %w", err)
	}
	info, err := certinfo.Inspect(certDER)
	if err != nil {
		return api.AttestedSVID{}, err
	}
	att.VerifiedAt = prepared.VerifiedAt
	response, err := json.Marshal(attestedProofEvidence{VerifiedAt: prepared.VerifiedAt})
	if err != nil {
		return api.AttestedSVID{}, err
	}
	nb, na := info.NotBefore, info.NotAfter
	sans := sansOf(info)
	if sans == nil {
		sans = []string{}
	}
	payload, err := json.Marshal(projections.CertificateRecorded{
		ID:   uuid.NewSHA1(uuid.NameSpaceOID, []byte("attested-proof-row-v1\x00"+key)).String(),
		CAID: s.caID, Subject: info.Subject, SANs: sans, Issuer: info.Issuer,
		Serial: info.SerialNumber, Fingerprint: info.SHA256Fingerprint,
		KeyAlgorithm: info.KeyAlgorithm, NotBefore: &nb, NotAfter: &na,
		Source: "attested:" + att.Method, CertificateDER: append([]byte(nil), certDER...),
		IssuanceIdempotencyKey: key, IssuanceRequestBinding: binding, IssuanceResponse: response,
		KeyOrigin: string(custody.OriginRequester), EnrollmentProtocol: "attested",
	})
	if err != nil {
		return api.AttestedSVID{}, err
	}
	if err := s.orch.RecordCertificateEvent(ctx, events.Event{ID: attestedProofEventID(key), Type: projections.EventCertificateRecorded, TenantID: tenantID, Data: payload}); err != nil {
		return api.AttestedSVID{}, err
	}
	return s.finish(ctx, tenantID, verifier, att, certDER, ttl, true)
}

func (s *attestedIssuerService) recoverAttestedProof(ctx context.Context, tenantID string, verifier *attest.Verifier, att attest.Attestation, row store.Certificate, binding string, ttl time.Duration) (api.AttestedSVID, error) {
	event, found, err := s.log.EventByID(ctx, attestedProofEventID(row.IssuanceIdempotencyKey))
	if err != nil {
		return api.AttestedSVID{}, err
	}
	if !found {
		return api.AttestedSVID{}, errors.New("server: attested proof certificate has no retained issuance event")
	}
	var retained projections.CertificateRecorded
	if event.Type != projections.EventCertificateRecorded || event.TenantID != tenantID || projections.ValidateSchemaVersion(event) != nil ||
		json.Unmarshal(event.Data, &retained) != nil || retained.IssuanceIdempotencyKey != row.IssuanceIdempotencyKey ||
		retained.Fingerprint != row.Fingerprint || retained.IssuanceRequestBinding != row.IssuanceRequestBinding ||
		!bytes.Equal(retained.CertificateDER, row.CertificateDER) {
		return api.AttestedSVID{}, errors.New("server: attested proof inventory differs from retained issuance")
	}
	if retained.IssuanceRequestBinding != binding {
		return api.AttestedSVID{}, fmt.Errorf("%w: attested proof already belongs to a different public key or command", orchestrator.ErrIdempotencyConflict)
	}
	var evidence attestedProofEvidence
	if err := json.Unmarshal(retained.IssuanceResponse, &evidence); err != nil || evidence.VerifiedAt.IsZero() {
		return api.AttestedSVID{}, errors.New("server: retained attested proof evidence is invalid")
	}
	att.VerifiedAt = evidence.VerifiedAt
	return s.finish(ctx, tenantID, verifier, att, retained.CertificateDER, ttl, false)
}
