// SPDX-License-Identifier: BUSL-1.1

package pqcmigration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/profile"
	"trstctl.com/trstctl/internal/store"
)

const migrationProtocolLeafTTL = 30 * 24 * time.Hour

type certificateExecutionBinding struct {
	Identity     store.Identity
	Target       store.DeploymentTarget
	AgentID      string
	IssuerSource string
	IssuerID     string
	Issuance     store.OperationApprovalIssuanceBinding
}

// A CBOM observation alone is not authority to issue a certificate or mutate
// a listener. The enrolled host later rechecks the public predecessor against
// its own files and TLS handshake before it generates a replacement key.
func (s *pqcMigrationService) preflightPQCReissues(ctx context.Context, tenantID string, plan Plan) (map[string]certificateExecutionBinding, error) {
	out := make(map[string]certificateExecutionBinding, len(plan.Reissues))
	for _, reissue := range plan.Reissues {
		identity, err := s.store.GetIdentity(ctx, tenantID, reissue.IdentityID)
		if err != nil {
			return nil, err
		}
		if identity.Kind != store.KindX509Certificate || identity.Status != "requested" {
			return nil, api.ErrStatus(http.StatusConflict, "PQC certificate migration requires a requested X.509 identity that has not issued a certificate")
		}
		var attrs struct {
			TargetID     string `json:"deployment_target_id"`
			ProfileName  string `json:"profile_name"`
			Algorithm    string `json:"subject_key_algorithm"`
			IssuerSource string `json:"issuing_authority_source"`
			IssuerID     string `json:"issuing_authority_id"`
		}
		if err := json.Unmarshal(identity.Attributes, &attrs); err != nil {
			return nil, api.ErrStatus(http.StatusConflict, "PQC identity attributes are not readable")
		}
		if attrs.TargetID != reissue.TargetID || attrs.Algorithm != TargetMLDSA65 ||
			strings.TrimSpace(attrs.ProfileName) == "" || strings.TrimSpace(identity.Name) == "" ||
			attrs.IssuerSource == "" || attrs.IssuerID == "" {
			return nil, api.ErrStatus(http.StatusConflict, "PQC identity must pin its bound target, ML-DSA-65 subject key, active profile, and exact issuing authority")
		}
		if attrs.IssuerSource != "platform" && attrs.IssuerSource != "private" {
			return nil, api.ErrStatus(http.StatusConflict, "PQC host certificate migration requires a signer-backed platform or managed private CA")
		}
		if attrs.IssuerSource == "platform" && attrs.IssuerID != "trstctl-issuing-ca" {
			return nil, api.ErrStatus(http.StatusConflict, "PQC platform CA identity does not match the served issuing CA")
		}
		target, err := s.store.GetDeploymentTarget(ctx, tenantID, reissue.TargetID)
		if err != nil {
			return nil, err
		}
		if !target.Enabled || !relay.SupportsPQCCertificatePredecessor(target.Type) {
			return nil, api.ErrStatus(http.StatusConflict, "PQC certificate target must be an enabled host connector with an exact certificate/key predecessor reader")
		}
		var config struct {
			Executor         string `json:"executor"`
			CertPath         string `json:"cert_path"`
			KeyPath          string `json:"key_path"`
			VerifyAddress    string `json:"verify_address"`
			VerifyServerName string `json:"verify_server_name"`
		}
		if err := json.Unmarshal(target.Config, &config); err != nil || config.Executor != "agent" ||
			config.CertPath == "" || config.KeyPath == "" || config.VerifyAddress != reissue.Asset.Location ||
			config.VerifyServerName != identity.Name {
			return nil, api.ErrStatus(http.StatusConflict, "PQC certificate target must route to its host agent, name its exact certificate/key files, and verify the observed listener with the identity DNS name")
		}
		agentID, err := s.store.ValidateHostTargetAssignment(ctx, tenantID, target.Type, target.Config)
		if err != nil {
			return nil, api.ErrWithStatus(http.StatusConflict, err)
		}
		if agentID == "" {
			return nil, api.ErrStatus(http.StatusConflict, "PQC certificate target has no enrolled host agent")
		}
		if _, err := s.store.GetOwner(ctx, tenantID, identity.OwnerID); err != nil {
			return nil, err
		}
		conflicts, err := s.store.ConflictingTargetBindings(ctx, tenantID, target.ID, identity.ID, "", true)
		if err != nil {
			return nil, err
		}
		if len(conflicts) != 0 {
			return nil, api.ErrStatus(http.StatusConflict, "PQC certificate target is already bound to another active identity")
		}
		rec, err := s.store.GetActiveProfile(ctx, tenantID, attrs.ProfileName)
		if err != nil {
			if store.IsNotFound(err) {
				return nil, api.ErrStatus(http.StatusConflict, "PQC identity's selected certificate profile is not active")
			}
			return nil, err
		}
		var selected profile.CertificateProfile
		if err := json.Unmarshal(rec.Spec, &selected); err != nil {
			return nil, fmt.Errorf("pqcmigration: decode active profile %q v%d: %w", rec.Name, rec.Version, err)
		}
		selected.Name, selected.Version = rec.Name, rec.Version
		if selected.RequiresApproval {
			return nil, api.ErrStatus(http.StatusConflict, "PQC certificate profile requires distinct issuance approval; approve the exact profile-bound operation before starting")
		}
		if err := validatePQCReissueProfile(selected, reissue.Asset, identity.Name, reissue.Protocol); err != nil {
			return nil, api.ErrStatus(http.StatusConflict, fmt.Sprintf("PQC reissue for asset %s cannot start under profile %s: %v", reissue.Asset.ID, rec.Name, err))
		}
		ttl := migrationProtocolLeafTTL
		if selected.MaxValidity > 0 && ttl > time.Duration(selected.MaxValidity) {
			ttl = time.Duration(selected.MaxValidity)
		}
		out[reissue.Asset.ID] = certificateExecutionBinding{
			Identity: identity, Target: target, AgentID: agentID,
			IssuerSource: attrs.IssuerSource, IssuerID: attrs.IssuerID,
			Issuance: store.OperationApprovalIssuanceBinding{
				ProfileName: rec.Name, ProfileID: rec.ID, ProfileVersion: rec.Version,
				ProfileSpecDigest:   store.ProfileSpecDigest(rec.Spec),
				RequestedTTLSeconds: int64(migrationProtocolLeafTTL / time.Second),
				EffectiveTTLSeconds: int64(ttl / time.Second),
			},
		}
	}
	return out, nil
}

func validatePQCReissueProfile(selected profile.CertificateProfile, asset Asset, dnsName, protocol string) error {
	if protocol != ProtocolHostCSR || asset.CertificateFingerprint == "" {
		return fmt.Errorf("selected certificate requires host-csr and an observed leaf fingerprint")
	}
	ttl := migrationProtocolLeafTTL
	if selected.MaxValidity > 0 && ttl > time.Duration(selected.MaxValidity) {
		ttl = time.Duration(selected.MaxValidity)
	}
	return selected.Validate(profile.Request{
		KeyAlgorithm: TargetMLDSA65, RequestedEKUs: selected.AllowedEKUs,
		TTL: ttl, DNSNames: []string{dnsName}, Protocol: "api",
	})
}
