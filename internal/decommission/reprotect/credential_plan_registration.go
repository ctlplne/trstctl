// SPDX-License-Identifier: BUSL-1.1

package reprotect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/decommission/depstate"
	corestore "trstctl.com/trstctl/internal/store"
)

var (
	ErrCredentialPlanTargetChanged = errors.New("reprotect: reviewed credential or host target changed")
	ErrCredentialPlanNotFound      = errors.New("reprotect: credential, authority, or host target not found in this tenant")
	ErrCredentialPlanNotReady      = errors.New("reprotect: credential or successor is not ready for host re-protection")
)

// CredentialPlanSelection contains only the operator's choices and the two
// readback values shown during review. Tenant, job, predecessor SPKI, route,
// agent, connector, and probe destination are derived from current product state.
type CredentialPlanSelection struct {
	CertificateID          string `json:"certificate_id"`
	SuccessorAuthorityID   string `json:"successor_authority_id"`
	TargetID               string `json:"target_id"`
	ExpectedTargetRevision string `json:"expected_target_revision"`
	ExpectedFingerprint    string `json:"expected_fingerprint"`
	TTLSeconds             int64  `json:"ttl_seconds"`
}

// RegisterCredentialPlan writes one immutable, public-only plan after proving
// that every selected object belongs to this tenant and that the predecessor
// was actually signed by the retiring CA. The worker repeats the revision,
// installed-key, and served-leaf checks immediately before each external effect.
func (e *Enqueuer) RegisterCredentialPlan(ctx context.Context, tenantID, keyID string, in CredentialPlanSelection) (CredentialPlan, bool, error) {
	if e == nil || e.store == nil || e.repo == nil || e.plans == nil {
		return CredentialPlan{}, false, ErrEnqueuerUnavailable
	}
	if tenantID == "" || keyID == "" || strings.TrimSpace(in.CertificateID) == "" ||
		strings.TrimSpace(in.SuccessorAuthorityID) == "" || strings.TrimSpace(in.TargetID) == "" ||
		strings.TrimSpace(in.ExpectedTargetRevision) == "" || strings.TrimSpace(in.ExpectedFingerprint) == "" ||
		in.TTLSeconds < 60 || in.TTLSeconds > 90*24*3600 {
		return CredentialPlan{}, false, fmt.Errorf("%w: certificate, successor, target, reviewed revision/fingerprint, and 60-second to 90-day TTL are required", ErrInvalidState)
	}
	state, found, err := e.repo.FetchKeyState(ctx, tenantID, keyID)
	if err != nil {
		return CredentialPlan{}, false, err
	}
	if !found {
		return CredentialPlan{}, false, ErrCredentialPlanNotFound
	}
	jobs, err := PlanFromState(state)
	if err != nil {
		return CredentialPlan{}, false, err
	}
	var selected Job
	for _, job := range jobs {
		if job.Kind == JobKindReIssue && job.Dependent.Class == depstate.DependentCredential && job.Dependent.ID == in.CertificateID {
			selected = job
			break
		}
	}
	if selected.ID == "" {
		return CredentialPlan{}, false, ErrCredentialPlanNotReady
	}
	oldCA, err := e.store.GetCAAuthority(ctx, tenantID, keyID)
	if err != nil {
		return CredentialPlan{}, false, credentialPlanReadError(err)
	}
	successor, err := e.store.GetCAAuthority(ctx, tenantID, in.SuccessorAuthorityID)
	if err != nil {
		return CredentialPlan{}, false, credentialPlanReadError(err)
	}
	if oldCA.Status != "superseded" || successor.Status != "active" || successor.ReplacesID == nil ||
		*successor.ReplacesID != oldCA.ID || successor.SignerHandle == "" || successor.CertificatePEM == "" {
		return CredentialPlan{}, false, ErrCredentialPlanNotReady
	}
	if successor.NotAfter != nil && time.Until(*successor.NotAfter) < time.Duration(in.TTLSeconds)*time.Second {
		return CredentialPlan{}, false, ErrCredentialPlanNotReady
	}
	cert, err := e.store.GetCertificate(ctx, tenantID, in.CertificateID)
	if err != nil {
		return CredentialPlan{}, false, credentialPlanReadError(err)
	}
	if cert.Status != "active" || len(cert.CertificateDER) == 0 || len(cert.CertificatePEM) == 0 ||
		cert.KeyOrigin != "host_agent" || cert.KeyStorage != "file" {
		return CredentialPlan{}, false, ErrCredentialPlanNotReady
	}
	info, err := certinfo.Inspect(cert.CertificateDER)
	if err != nil || info.IsCA || info.SHA256Fingerprint != cert.Fingerprint {
		return CredentialPlan{}, false, ErrCredentialPlanNotReady
	}
	if cert.Fingerprint != in.ExpectedFingerprint {
		return CredentialPlan{}, false, ErrCredentialPlanTargetChanged
	}
	bindings, err := e.store.CertificateIdentityBindings(ctx, tenantID, []string{cert.ID})
	if err != nil {
		return CredentialPlan{}, false, err
	}
	identityIDs := bindings[cert.ID]
	if len(identityIDs) != 1 {
		return CredentialPlan{}, false, ErrCredentialPlanNotReady
	}
	identity, err := e.store.GetIdentity(ctx, tenantID, identityIDs[0])
	if err != nil {
		return CredentialPlan{}, false, credentialPlanReadError(err)
	}
	var identityRoute struct {
		DeploymentTargetID     string `json:"deployment_target_id"`
		IssuingAuthoritySource string `json:"issuing_authority_source"`
		IssuingAuthorityID     string `json:"issuing_authority_id"`
	}
	if identity.Kind != corestore.KindX509Certificate || identity.Status != "deployed" ||
		json.Unmarshal(identity.Attributes, &identityRoute) != nil ||
		identityRoute.DeploymentTargetID != in.TargetID ||
		identityRoute.IssuingAuthoritySource != "private" || identityRoute.IssuingAuthorityID != keyID {
		return CredentialPlan{}, false, ErrCredentialPlanNotReady
	}
	oldDER, err := certinfo.LeafDER([]byte(oldCA.CertificatePEM))
	if err != nil || crypto.VerifyLeafSignedByCA(cert.CertificateDER, oldDER) != nil {
		return CredentialPlan{}, false, ErrCredentialPlanNotReady
	}
	target, err := e.store.GetDeploymentTarget(ctx, tenantID, in.TargetID)
	if err != nil {
		return CredentialPlan{}, false, credentialPlanReadError(err)
	}
	if !target.Enabled || target.RevisionID != in.ExpectedTargetRevision {
		return CredentialPlan{}, false, ErrCredentialPlanTargetChanged
	}
	if !relay.SupportsPQCCertificatePredecessor(target.Type) {
		return CredentialPlan{}, false, ErrCredentialPlanNotReady
	}
	var host struct {
		CertPath         string `json:"cert_path"`
		KeyPath          string `json:"key_path"`
		VerifyAddress    string `json:"verify_address"`
		VerifyServerName string `json:"verify_server_name"`
	}
	if json.Unmarshal(target.Config, &host) != nil || host.CertPath == "" || host.KeyPath == "" ||
		host.VerifyAddress == "" || host.VerifyServerName == "" ||
		certinfo.VerifyHostname(cert.CertificateDER, host.VerifyServerName) != nil {
		return CredentialPlan{}, false, ErrCredentialPlanNotReady
	}
	agentID, err := e.store.ValidateHostTargetAssignment(ctx, tenantID, target.Type, target.Config)
	if err != nil || agentID == "" {
		return CredentialPlan{}, false, ErrCredentialPlanNotReady
	}
	plan := CredentialPlan{Job: selected, IdentityID: identity.ID, SuccessorAuthorityID: successor.ID,
		PredecessorFingerprint: cert.Fingerprint, PredecessorSPKISHA256: info.SPKISHA256,
		TargetID: target.ID, TargetRevisionID: target.RevisionID, RequiredAgentID: agentID,
		Connector: target.Type, VerifyAddress: host.VerifyAddress,
		VerifyServerName: host.VerifyServerName, TTLSeconds: in.TTLSeconds}
	recorded, err := e.plans.Record(ctx, plan)
	return plan, recorded, err
}

func credentialPlanReadError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrCredentialPlanNotFound
	}
	return err
}
