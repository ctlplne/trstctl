// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// TPM-held host keys (TPM-O1).
//
// A profile's host_key_attestation policy moves a host-generated renewal's
// key from the agent's locked memory into the host's TPM. The renewal job is
// queued with key_custody "tpm"; the agent has the TPM create the key and sign
// the CSR, and sends the TPM's TPM2_Certify of that key by an attestation key
// whose certificate chains to one of the profile's roots, over SHA-256 of the
// job's host-key binding. Nothing is signed for such a job without that proof,
// and the certificate's custody is then the device-bound claim it supports,
// recorded with the evidence so it can be checked again offline.

// hostKeyAttestationPolicy is the served profile's host key attestation policy
// for a renewal under binding; a tenant with no served profile has none (the
// signing path's profile check fails closed on a missing configured profile).
func (d *issuanceDispatcher) hostKeyAttestationPolicy(ctx context.Context, tenantID string, binding *store.OperationApprovalIssuanceBinding) (profile.HostKeyAttestationPolicy, error) {
	rec, name, found, err := servedIssuanceProfile(ctx, d.store, d.defaultProfile, tenantID, binding)
	if errors.Is(err, errServedDefaultProfileMissing) {
		return profile.HostKeyAttestationPolicy{}, nil
	}
	if err != nil {
		return profile.HostKeyAttestationPolicy{}, err
	}
	if !found {
		return profile.HostKeyAttestationPolicy{}, nil
	}
	var prof profile.CertificateProfile
	if err := json.Unmarshal(rec.Spec, &prof); err != nil {
		return profile.HostKeyAttestationPolicy{}, fmt.Errorf("server: decode profile %q: %w", name, err)
	}
	return prof.HostKeyAttestation, nil
}

// hostRenewalKeyCustody is the key custody a host renewal is queued with: the
// TPM when the served profile requires it, else the agent's locked memory.
func (d *issuanceDispatcher) hostRenewalKeyCustody(ctx context.Context, tenantID string, target store.DeploymentTarget,
	binding *store.OperationApprovalIssuanceBinding) (string, error) {
	policy, err := d.hostKeyAttestationPolicy(ctx, tenantID, binding)
	if err != nil {
		return "", err
	}
	if !policy.Required {
		return "", nil
	}
	if connectors := relay.TPMHostKeyConnectors(); !slices.Contains(connectors, target.Type) {
		return "", fmt.Errorf("server: the profile requires host keys held in the host's TPM, and the %s connector cannot install one (%s can)",
			target.Type, strings.Join(connectors, ", "))
	}
	return relay.HostKeyCustodyTPM, nil
}

// verifyHostKeyAttestation checks a renewal CSR's key attestation against the
// job and the served profile, and returns the evidence to keep; nil when the
// job asks for none. issuance names the profile: the renewal's own, or a CA
// re-protection's identity profile (TPM-O1-L1).
func (d *issuanceDispatcher) verifyHostKeyAttestation(ctx context.Context, tenantID string, jobID int64, intent RelayDeployIntent,
	issuance *store.OperationApprovalIssuanceBinding, csrDER, keyAttestation []byte) (*ca.DeviceAttestation, error) {
	custody := strings.TrimSpace(intent.KeyCustody)
	if custody != "" && custody != relay.HostKeyCustodyTPM {
		return nil, status.Errorf(codes.FailedPrecondition, "this renewal job names key custody %q, which no agent provides", custody)
	}
	policy, err := d.hostKeyAttestationPolicy(ctx, tenantID, issuance)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the profile's host key attestation policy: %v", err)
	}
	switch {
	case custody == "" && !policy.Required:
		if len(keyAttestation) > 0 {
			return nil, status.Error(codes.InvalidArgument, "this renewal job asks for no key attestation")
		}
		return nil, nil
	case custody == "":
		return nil, status.Error(codes.FailedPrecondition,
			"the profile now requires host keys held in the host's TPM, and this job was queued before it did; the next renewal makes its key there")
	case len(keyAttestation) == 0:
		return nil, status.Error(codes.PermissionDenied,
			"this renewal requires a key the host's TPM holds and attests, and the request carries no attestation")
	case !policy.Required || len(policy.AttestationRootsPEM) == 0:
		return nil, status.Error(codes.FailedPrecondition, "the profile no longer names TPM attestation roots for this renewal's key")
	}
	roots := make([][]byte, 0, len(policy.AttestationRootsPEM))
	for _, root := range policy.AttestationRootsPEM {
		roots = append(roots, []byte(root))
	}
	binding, err := deviceattest.HostKeyBinding(jobID, csrDER)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "the renewal CSR cannot be bound for attestation: %v", err)
	}
	now := time.Now().UTC()
	result, err := deviceattest.VerifyHostKeyAttestation(keyAttestation, binding, csrDER, roots, now)
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "the renewal key's TPM attestation was not accepted: %v", err)
	}
	return &ca.DeviceAttestation{
		Format:                       "tpm-webauthn",
		Credential:                   append([]byte(nil), keyAttestation...),
		Binding:                      binding,
		PublicKeySHA256:              result.PublicKeySHA256,
		AttestationCertificateSHA256: result.AttestationCertificateSHA256,
		TrustedRootsSHA256:           crypto.SHA256Sum(bytes.Join(roots, []byte("\n"))),
		VerifiedAt:                   now,
	}, nil
}

// attestHostKeyCustody records the issued certificate's custody as the
// device-bound claim its key's attestation proves. A retried signing whose
// earlier attempt recorded the claim before its reply was lost brings a fresh
// TPM certification of the same key; the claim already kept for that key
// stands.
func (d *issuanceDispatcher) attestHostKeyCustody(ctx context.Context, tenantID, agentName, fingerprint string, evidence *ca.DeviceAttestation) error {
	err := d.orch.AttestCertificateDeviceCustody(ctx, tenantID, projections.CertificateCustodyDeviceAttested{
		Fingerprint:                  fingerprint,
		Source:                       projections.CertificateDeviceAttestationSourceHostAgentTPM,
		Format:                       evidence.Format,
		KeyGeneratedBy:               agentName,
		Credential:                   evidence.Credential,
		Binding:                      evidence.Binding,
		PublicKeySHA256:              evidence.PublicKeySHA256,
		AttestationCertificateSHA256: evidence.AttestationCertificateSHA256,
		TrustedRootsSHA256:           evidence.TrustedRootsSHA256,
		VerifiedAt:                   evidence.VerifiedAt,
	})
	if err == nil {
		return nil
	}
	cert, getErr := d.store.GetCertificateByFingerprint(ctx, tenantID, fingerprint)
	if getErr != nil {
		return err
	}
	kept, keptErr := d.store.GetCertificateKeyAttestation(ctx, tenantID, cert.ID)
	if keptErr == nil && kept.Source == projections.CertificateDeviceAttestationSourceHostAgentTPM &&
		bytes.Equal(kept.PublicKeySHA256, evidence.PublicKeySHA256) {
		return nil
	}
	return err
}
