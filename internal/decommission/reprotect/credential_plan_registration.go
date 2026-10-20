// SPDX-License-Identifier: BUSL-1.1

package reprotect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/profile"
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
	plan, err := e.PreviewCredentialPlan(ctx, tenantID, keyID, in)
	if err != nil {
		return CredentialPlan{}, false, err
	}
	if e.plans == nil {
		return CredentialPlan{}, false, ErrEnqueuerUnavailable
	}
	recorded, err := e.plans.Record(ctx, plan)
	if err != nil || recorded {
		return plan, recorded, err
	}
	// A lost response may retry after a newer active policy revision was
	// selected. Return the actual first-writer plan, never a freshly derived
	// object that was not recorded.
	current, found, err := e.plans.Load(ctx, tenantID, plan.Job.ID)
	if err != nil {
		return CredentialPlan{}, false, err
	}
	if !found {
		return CredentialPlan{}, false, ErrCompletionConflict
	}
	if !sameCurrentHostPlan(current, plan) {
		return CredentialPlan{}, false, ErrCredentialPlanTargetChanged
	}
	return current, false, nil
}

// PreviewCredentialPlan derives the exact command from current tenant state
// without appending an event, enqueueing work, or contacting the signer/host.
// Registration repeats every check against fresh state after operator review.
func (e *Enqueuer) PreviewCredentialPlan(ctx context.Context, tenantID, keyID string, in CredentialPlanSelection) (CredentialPlan, error) {
	if e == nil || e.store == nil || e.repo == nil {
		return CredentialPlan{}, ErrEnqueuerUnavailable
	}
	if tenantID == "" || keyID == "" || strings.TrimSpace(in.CertificateID) == "" ||
		strings.TrimSpace(in.SuccessorAuthorityID) == "" || strings.TrimSpace(in.TargetID) == "" ||
		strings.TrimSpace(in.ExpectedTargetRevision) == "" || strings.TrimSpace(in.ExpectedFingerprint) == "" ||
		in.TTLSeconds < 60 || in.TTLSeconds > 90*24*3600 {
		return CredentialPlan{}, fmt.Errorf("%w: certificate, successor, target, reviewed revision/fingerprint, and 60-second to 90-day TTL are required", ErrInvalidState)
	}
	for _, id := range []string{keyID, in.CertificateID, in.SuccessorAuthorityID, in.TargetID} {
		if _, err := uuid.Parse(id); err != nil {
			return CredentialPlan{}, fmt.Errorf("%w: predecessor, certificate, successor and target IDs must be UUIDs", ErrInvalidState)
		}
	}
	state, found, err := e.repo.FetchKeyState(ctx, tenantID, keyID)
	if err != nil {
		return CredentialPlan{}, err
	}
	if !found {
		return CredentialPlan{}, ErrCredentialPlanNotFound
	}
	jobs, err := PlanFromState(state)
	if err != nil {
		return CredentialPlan{}, err
	}
	var selected Job
	for _, job := range jobs {
		if job.Kind == JobKindReIssue && job.Dependent.Class == depstate.DependentCredential && job.Dependent.ID == in.CertificateID {
			selected = job
			break
		}
	}
	if selected.ID == "" {
		return CredentialPlan{}, ErrCredentialPlanNotReady
	}
	oldCA, err := e.store.GetCAAuthority(ctx, tenantID, keyID)
	if err != nil {
		return CredentialPlan{}, credentialPlanReadError(err)
	}
	successor, err := e.store.GetCAAuthority(ctx, tenantID, in.SuccessorAuthorityID)
	if err != nil {
		return CredentialPlan{}, credentialPlanReadError(err)
	}
	if oldCA.Status != "superseded" || successor.Status != "active" || successor.ReplacesID == nil ||
		*successor.ReplacesID != oldCA.ID || successor.SignerHandle == "" || successor.CertificatePEM == "" {
		return CredentialPlan{}, ErrCredentialPlanNotReady
	}
	if successor.NotAfter != nil && time.Until(*successor.NotAfter) < time.Duration(in.TTLSeconds)*time.Second {
		return CredentialPlan{}, ErrCredentialPlanNotReady
	}
	cert, err := e.store.GetCertificate(ctx, tenantID, in.CertificateID)
	if err != nil {
		return CredentialPlan{}, credentialPlanReadError(err)
	}
	if cert.Status != "active" || len(cert.CertificateDER) == 0 || len(cert.CertificatePEM) == 0 ||
		cert.KeyOrigin != "host_agent" || cert.KeyStorage != "file" {
		return CredentialPlan{}, ErrCredentialPlanNotReady
	}
	info, err := certinfo.Inspect(cert.CertificateDER)
	if err != nil || info.IsCA || info.SHA256Fingerprint != cert.Fingerprint {
		return CredentialPlan{}, ErrCredentialPlanNotReady
	}
	if cert.Fingerprint != in.ExpectedFingerprint {
		return CredentialPlan{}, ErrCredentialPlanTargetChanged
	}
	bindings, err := e.store.CertificateIdentityBindings(ctx, tenantID, []string{cert.ID})
	if err != nil {
		return CredentialPlan{}, err
	}
	identityIDs := bindings[cert.ID]
	if len(identityIDs) != 1 {
		return CredentialPlan{}, ErrCredentialPlanNotReady
	}
	identity, err := e.store.GetIdentity(ctx, tenantID, identityIDs[0])
	if err != nil {
		return CredentialPlan{}, credentialPlanReadError(err)
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
		return CredentialPlan{}, ErrCredentialPlanNotReady
	}
	profileName, err := e.validateCurrentCertificatePolicy(ctx, tenantID, identity.ID, info, in.TTLSeconds)
	if err != nil {
		return CredentialPlan{}, err
	}
	oldDER, err := certinfo.LeafDER([]byte(oldCA.CertificatePEM))
	if err != nil || crypto.VerifyLeafSignedByCA(cert.CertificateDER, oldDER) != nil {
		return CredentialPlan{}, ErrCredentialPlanNotReady
	}
	target, err := e.store.GetDeploymentTarget(ctx, tenantID, in.TargetID)
	if err != nil {
		return CredentialPlan{}, credentialPlanReadError(err)
	}
	if !target.Enabled || target.RevisionID != in.ExpectedTargetRevision {
		return CredentialPlan{}, ErrCredentialPlanTargetChanged
	}
	if !relay.SupportsPQCCertificatePredecessor(target.Type) {
		return CredentialPlan{}, ErrCredentialPlanNotReady
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
		return CredentialPlan{}, ErrCredentialPlanNotReady
	}
	agentID, err := e.store.ValidateHostTargetAssignment(ctx, tenantID, target.Type, target.Config)
	if err != nil || agentID == "" {
		return CredentialPlan{}, ErrCredentialPlanNotReady
	}
	plan := CredentialPlan{Job: selected, IdentityID: identity.ID, ProfileName: profileName, SuccessorAuthorityID: successor.ID,
		PredecessorFingerprint: cert.Fingerprint, PredecessorSPKISHA256: info.SPKISHA256,
		TargetID: target.ID, TargetRevisionID: target.RevisionID, RequiredAgentID: agentID,
		Connector: target.Type, VerifyAddress: host.VerifyAddress,
		VerifyServerName: host.VerifyServerName, TTLSeconds: in.TTLSeconds}
	return plan, nil
}

// The reviewed plan is executable only under the identity's selected active
// policy. An absent identity selection uses the deployment default. The
// administrative continuation has no enrollment protocol, but all public
// certificate properties and the requested lifetime remain bounded.
func (e *Enqueuer) validateCurrentCertificatePolicy(ctx context.Context, tenantID, identityID string, info certinfo.Info, ttlSeconds int64) (string, error) {
	resolver := e.profileOrch
	if resolver == nil {
		resolver = orchestrator.NewOrchestrator(e.log, e.store, nil)
	}
	requirement, err := resolver.ProfileApprovalRequirement(ctx, tenantID, identityID)
	if err != nil {
		return "", fmt.Errorf("%w: resolve identity certificate policy: %v", ErrCredentialPlanNotReady, err)
	}
	name := requirement.ProfileName
	if name == "" {
		name = strings.TrimSpace(e.defaultProfile)
	}
	if name == "" {
		return "", nil
	}
	rec, err := e.store.GetActiveProfile(ctx, tenantID, name)
	if err != nil {
		return "", fmt.Errorf("%w: selected certificate policy %q is unavailable: %v", ErrCredentialPlanNotReady, name, err)
	}
	var policy profile.CertificateProfile
	if err := json.Unmarshal(rec.Spec, &policy); err != nil {
		return "", fmt.Errorf("%w: decode selected certificate policy %q: %v", ErrCredentialPlanNotReady, name, err)
	}
	policy.Name, policy.Version = rec.Name, rec.Version
	if err := policy.Validate(profile.Request{
		KeyAlgorithm: info.KeyAlgorithm, KeyBits: info.PublicKeyBits, RequestedEKUs: info.ExtKeyUsages,
		TTL: time.Duration(ttlSeconds) * time.Second, DNSNames: info.DNSNames,
		IPAddresses: info.IPAddresses, EmailAddresses: info.EmailAddresses, URIs: info.URIs,
	}); err != nil {
		return "", fmt.Errorf("%w: selected certificate policy rejects the reviewed successor: %v", ErrCredentialPlanNotReady, err)
	}
	return name, nil
}

// LoadCredentialPlan reads only the first-writer plan for this tenant and CA.
func (e *Enqueuer) LoadCredentialPlan(ctx context.Context, tenantID, keyID, jobID string) (CredentialPlan, bool, error) {
	if e == nil || e.plans == nil {
		return CredentialPlan{}, false, ErrEnqueuerUnavailable
	}
	plan, found, err := e.plans.Load(ctx, tenantID, jobID)
	if err != nil || !found {
		return CredentialPlan{}, found, err
	}
	if plan.Job.KeyID != keyID {
		return CredentialPlan{}, false, nil
	}
	return plan, true, nil
}

func credentialPlanReadError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrCredentialPlanNotFound
	}
	return err
}
