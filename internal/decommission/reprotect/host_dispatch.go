// SPDX-License-Identifier: BUSL-1.1

package reprotect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
	decstore "trstctl.com/trstctl/internal/decommission/store"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	corestore "trstctl.com/trstctl/internal/store"
)

const hostReprotectDestination = "endpoint.renew"

// hostReprotectIntent is public routing and certificate metadata only. Its JSON
// contract is consumed by the host agent and re-read by SignJobCSR; no subject
// key or management credential is ever placed in this outbox payload.
type hostReprotectIntent struct {
	Connector                       string          `json:"connector"`
	Target                          string          `json:"target"`
	TargetID                        string          `json:"target_id"`
	Revision                        string          `json:"target_revision"`
	IdentityID                      string          `json:"identity_id"`
	TargetConfig                    json.RawMessage `json:"target_config"`
	CredentialRefs                  []string        `json:"credential_refs,omitempty"`
	VerifyAddress                   string          `json:"verify_address"`
	VerifyServerName                string          `json:"verify_server_name"`
	SubjectCommonName               string          `json:"subject_common_name"`
	SubjectDNSNames                 []string        `json:"subject_dns_names"`
	PredecessorCertificateID        string          `json:"predecessor_certificate_id"`
	IssuingAuthoritySource          string          `json:"issuing_authority_source"`
	IssuingAuthorityID              string          `json:"issuing_authority_id"`
	RequiredAgentID                 string          `json:"required_agent_id"`
	ReprotectJobID                  string          `json:"reprotect_job_id"`
	ReprotectPredecessorFingerprint string          `json:"reprotect_predecessor_fingerprint"`
	ReprotectPredecessorSPKISHA256  string          `json:"reprotect_predecessor_spki_sha256"`
	ReprotectTTLSeconds             int64           `json:"reprotect_ttl_seconds"`
	ReprotectProfileName            string          `json:"reprotect_profile_name,omitempty"`
}

func (h Handler) dispatchHostCredentialReissue(ctx context.Context, job Job, successorID string) error {
	if h.coreStore == nil || h.store == nil || h.plans == nil || h.outbox == nil {
		return ErrExecutorUnavailable
	}
	if err := validateJob(job); err != nil {
		return err
	}
	if successorID == "" {
		return ErrCredentialPlanRequired
	}
	childKey := "vdec-host-reprotect:" + crypto.SHA256Hex([]byte(job.TenantID+"\x1f"+job.ID))
	// A parent redelivery after the child was queued must acknowledge the same
	// durable command even if a later successful cutover changed current state.
	if _, err := h.coreStore.GetOutboxAttemptByKey(ctx, job.TenantID, hostReprotectDestination, childKey); err == nil {
		return nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	plan, found, err := h.plans.Load(ctx, job.TenantID, job.ID)
	if err != nil {
		return err
	}
	if !found || !samePlannedHostJob(plan.Job, job) || plan.SuccessorAuthorityID != successorID {
		return ErrCompletionConflict
	}
	selection := CredentialPlanSelection{CertificateID: job.Dependent.ID, SuccessorAuthorityID: successorID,
		TargetID: plan.TargetID, ExpectedTargetRevision: plan.TargetRevisionID,
		ExpectedFingerprint: plan.PredecessorFingerprint, TTLSeconds: plan.TTLSeconds}
	current, err := NewEnqueuer(h.coreStore, h.store, nil).WithProfilePolicy(h.log, h.defaultProfile).PreviewCredentialPlan(ctx, job.TenantID, job.KeyID, selection)
	if err != nil || !sameCurrentHostPlan(plan, current) {
		if err != nil {
			return err
		}
		return ErrCredentialPlanTargetChanged
	}
	cert, err := h.coreStore.GetCertificate(ctx, job.TenantID, job.Dependent.ID)
	if err != nil {
		return err
	}
	info, err := certinfo.Inspect(cert.CertificateDER)
	if err != nil {
		return err
	}
	if len(info.DNSNames) == 0 || len(info.IPAddresses) != 0 || len(info.EmailAddresses) != 0 || len(info.URIs) != 0 {
		return fmt.Errorf("%w: this host CSR path cannot preserve a non-DNS certificate identifier", ErrCredentialPlanNotReady)
	}
	target, err := h.coreStore.GetDeploymentTargetRevision(ctx, job.TenantID, plan.TargetID, plan.TargetRevisionID)
	if err != nil {
		return err
	}
	if !target.Enabled || target.Type != plan.Connector {
		return ErrCredentialPlanTargetChanged
	}
	intent := hostReprotectIntent{Connector: plan.Connector, Target: target.Name, TargetID: plan.TargetID,
		Revision: plan.TargetRevisionID, IdentityID: plan.IdentityID,
		TargetConfig: target.Config, CredentialRefs: hostReprotectSecretRefs(target.Config),
		VerifyAddress: plan.VerifyAddress, VerifyServerName: plan.VerifyServerName,
		SubjectCommonName: info.CommonName, SubjectDNSNames: info.DNSNames,
		PredecessorCertificateID: job.Dependent.ID, IssuingAuthoritySource: "private",
		IssuingAuthorityID: successorID, RequiredAgentID: plan.RequiredAgentID,
		ReprotectJobID: job.ID, ReprotectPredecessorFingerprint: plan.PredecessorFingerprint,
		ReprotectPredecessorSPKISHA256: plan.PredecessorSPKISHA256, ReprotectTTLSeconds: plan.TTLSeconds,
		ReprotectProfileName: plan.ProfileName}
	payload, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	return h.coreStore.WithTenant(ctx, job.TenantID, func(tx pgx.Tx) error {
		_, err := h.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID: job.TenantID, Destination: hostReprotectDestination,
			IdempotencyKey: childKey, Payload: payload,
			EffectLane:        hostReprotectDestination + ":identity:" + plan.IdentityID,
			RequiredAgentRole: mtls.AgentRoleHost, RequiredAgentID: plan.RequiredAgentID,
		})
		return err
	})
}

// AuthorizeHostCSR re-derives the reviewed plan from current tenant state
// while the caller holds the identity issuance fence. The outbox child is a
// routing instruction, not authority to ask the signer for a different key,
// names, CA, target, TTL, or host agent.
func AuthorizeHostCSR(ctx context.Context, st *corestore.Store, log *events.Log,
	tenantID, agentID, jobKey string, payload, csrDER []byte, defaultProfile string) (CredentialPlan, error) {
	if st == nil || log == nil || tenantID == "" || agentID == "" {
		return CredentialPlan{}, ErrExecutorUnavailable
	}
	var intent hostReprotectIntent
	if err := json.Unmarshal(payload, &intent); err != nil || intent.ReprotectJobID == "" {
		return CredentialPlan{}, ErrCredentialPlanRequired
	}
	if jobKey != "vdec-host-reprotect:"+crypto.SHA256Hex([]byte(tenantID+"\x1f"+intent.ReprotectJobID)) {
		return CredentialPlan{}, ErrCompletionConflict
	}
	plan, found, err := NewCredentialPlanLedger(log, st).Load(ctx, tenantID, intent.ReprotectJobID)
	if err != nil {
		return CredentialPlan{}, err
	}
	if !found || plan.RequiredAgentID != agentID {
		return CredentialPlan{}, ErrCredentialPlanNotReady
	}
	predecessor, err := st.GetCertificate(ctx, tenantID, plan.Job.Dependent.ID)
	if err != nil {
		return CredentialPlan{}, err
	}
	if err := validateHostCSRPublicBinding(plan, intent, predecessor, csrDER); err != nil {
		return CredentialPlan{}, fmt.Errorf("reprotect: retained CSR and immutable plan binding: %w", err)
	}
	selection := CredentialPlanSelection{CertificateID: plan.Job.Dependent.ID, SuccessorAuthorityID: plan.SuccessorAuthorityID,
		TargetID: plan.TargetID, ExpectedTargetRevision: plan.TargetRevisionID,
		ExpectedFingerprint: plan.PredecessorFingerprint, TTLSeconds: plan.TTLSeconds}
	current, err := NewEnqueuer(st, decstore.New(st), nil).WithProfilePolicy(log, defaultProfile).PreviewCredentialPlan(ctx, tenantID, plan.Job.KeyID, selection)
	if err != nil || !sameCurrentHostPlan(plan, current) {
		if err != nil {
			return CredentialPlan{}, err
		}
		return CredentialPlan{}, fmt.Errorf("reprotect: current tenant plan differs from immutable plan: %w", ErrCredentialPlanTargetChanged)
	}
	target, err := st.GetDeploymentTarget(ctx, tenantID, plan.TargetID)
	if err != nil {
		return CredentialPlan{}, err
	}
	if !sameHostTargetConfig(target.Config, intent.TargetConfig) {
		return CredentialPlan{}, fmt.Errorf("reprotect: target config differs from bound host job: %w", ErrCredentialPlanTargetChanged)
	}
	return plan, nil
}

// The dependency ledger can advance for a different leaf after this plan is
// recorded. Its position is a source watermark, not part of this leaf's
// authority. Accept only forward movement and require every stable job field
// and every certificate, successor, host, route, and TTL binding to match.
func samePlannedHostJob(recorded, current Job) bool {
	if current.LedgerPosition < recorded.LedgerPosition {
		return false
	}
	current.LedgerPosition = recorded.LedgerPosition
	return current == recorded
}

func sameCurrentHostPlan(recorded, current CredentialPlan) bool {
	if !samePlannedHostJob(recorded.Job, current.Job) {
		return false
	}
	current.Job.LedgerPosition = recorded.Job.LedgerPosition
	// Plans recorded before profile selection was included retain their exact
	// predecessor/host authority. Resolve their current policy at every use.
	if recorded.ProfileName == "" {
		current.ProfileName = ""
	}
	return reflect.DeepEqual(current, recorded)
}

func sameHostTargetConfig(current, queued json.RawMessage) bool {
	var a, b any
	return json.Unmarshal(current, &a) == nil && json.Unmarshal(queued, &b) == nil && reflect.DeepEqual(a, b)
}

// The predecessor certificate and self-signed CSR are both public. This check
// compares every identifier and the SPKI, so a re-protection cannot silently
// become a key rotation or expand the certificate's identity.
func validateHostCSRPublicBinding(plan CredentialPlan, intent hostReprotectIntent,
	predecessor corestore.Certificate, csrDER []byte) error {
	if err := validateHostIntentBinding(plan, intent, predecessor); err != nil {
		return err
	}
	old, err := certinfo.Inspect(predecessor.CertificateDER)
	if err != nil {
		return ErrCredentialPlanTargetChanged
	}
	csr, err := crypto.InspectCSR(csrDER)
	if err != nil || csr.CommonName != old.CommonName || !sameHostIdentifiers(csr.DNSNames, old.DNSNames) ||
		len(csr.IPAddresses) != 0 || len(csr.EmailAddresses) != 0 || len(csr.URIs) != 0 {
		return ErrCredentialPlanTargetChanged
	}
	public, err := crypto.InspectOpaqueCSR(csrDER)
	if err != nil || crypto.SHA256Hex(public.RawSubjectPublicKeyInfo) != plan.PredecessorSPKISHA256 {
		return ErrCredentialPlanTargetChanged
	}
	return nil
}

func validateHostIntentBinding(plan CredentialPlan, intent hostReprotectIntent, predecessor corestore.Certificate) error {
	if plan.IdentityID != intent.IdentityID || plan.TargetID != intent.TargetID ||
		plan.TargetRevisionID != intent.Revision || plan.Connector != intent.Connector ||
		plan.RequiredAgentID != intent.RequiredAgentID || plan.Job.ID != intent.ReprotectJobID ||
		plan.Job.Dependent.ID != intent.PredecessorCertificateID ||
		plan.SuccessorAuthorityID != intent.IssuingAuthorityID || intent.IssuingAuthoritySource != "private" ||
		plan.PredecessorFingerprint != intent.ReprotectPredecessorFingerprint ||
		plan.PredecessorSPKISHA256 != intent.ReprotectPredecessorSPKISHA256 ||
		plan.ProfileName != intent.ReprotectProfileName ||
		plan.TTLSeconds != intent.ReprotectTTLSeconds || plan.VerifyAddress != intent.VerifyAddress ||
		plan.VerifyServerName != intent.VerifyServerName || predecessor.ID != plan.Job.Dependent.ID ||
		predecessor.Fingerprint != plan.PredecessorFingerprint {
		return ErrCompletionConflict
	}
	old, err := certinfo.Inspect(predecessor.CertificateDER)
	if err != nil || old.SHA256Fingerprint != plan.PredecessorFingerprint || old.SPKISHA256 != plan.PredecessorSPKISHA256 ||
		old.IsCA || old.CommonName != intent.SubjectCommonName || !sameHostIdentifiers(old.DNSNames, intent.SubjectDNSNames) {
		return ErrCredentialPlanTargetChanged
	}
	return nil
}

func sameHostIdentifiers(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	count := make(map[string]int, len(a))
	for _, item := range a {
		count[item]++
	}
	for _, item := range b {
		if count[item] == 0 {
			return false
		}
		count[item]--
	}
	return true
}

func hostReprotectSecretRefs(raw json.RawMessage) []string {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return nil
	}
	seen := map[string]bool{}
	var walk func(any)
	walk = func(v any) {
		switch item := v.(type) {
		case string:
			if ref := strings.TrimSpace(item); strings.HasPrefix(ref, "secret://") {
				seen[ref] = true
			}
		case map[string]any:
			for _, child := range item {
				walk(child)
			}
		case []any:
			for _, child := range item {
				walk(child)
			}
		}
	}
	walk(value)
	refs := make([]string, 0, len(seen))
	for ref := range seen {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}
