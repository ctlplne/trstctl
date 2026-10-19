// SPDX-License-Identifier: BUSL-1.1

package reprotect

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	corestore "trstctl.com/trstctl/internal/store"
)

// AuthorizeVerifiedHostResult checks the certificate named by a signed,
// verified agent report against the retained immutable plan before the
// predecessor and identity authority are cut over. It cannot infer success
// from a job status or an unsigned certificate inventory row.
func AuthorizeVerifiedHostResult(ctx context.Context, st *corestore.Store, log *events.Log,
	tenantID, agentID, jobKey string, jobID int64, payload []byte, newFingerprint string,
	attempt int) (corestore.CertificateReprotectionCutover, error) {
	if st == nil || log == nil || tenantID == "" || agentID == "" || jobID <= 0 || attempt <= 0 || newFingerprint == "" {
		return corestore.CertificateReprotectionCutover{}, ErrExecutorUnavailable
	}
	var intent hostReprotectIntent
	if json.Unmarshal(payload, &intent) != nil || intent.ReprotectJobID == "" {
		return corestore.CertificateReprotectionCutover{}, ErrCredentialPlanRequired
	}
	if jobKey != "vdec-host-reprotect:"+crypto.SHA256Hex([]byte(tenantID+"\x1f"+intent.ReprotectJobID)) {
		return corestore.CertificateReprotectionCutover{}, ErrCompletionConflict
	}
	plan, found, err := NewCredentialPlanLedger(log, st).Load(ctx, tenantID, intent.ReprotectJobID)
	if err != nil {
		return corestore.CertificateReprotectionCutover{}, err
	}
	if !found || plan.RequiredAgentID != agentID {
		return corestore.CertificateReprotectionCutover{}, ErrCredentialPlanNotReady
	}
	old, err := st.GetCertificate(ctx, tenantID, plan.Job.Dependent.ID)
	if err != nil {
		return corestore.CertificateReprotectionCutover{}, err
	}
	if err := validateHostIntentBinding(plan, intent, old); err != nil {
		return corestore.CertificateReprotectionCutover{}, err
	}
	if old.Status != "active" && old.Status != "superseded" {
		return corestore.CertificateReprotectionCutover{}, ErrCredentialPlanTargetChanged
	}
	target, err := st.GetDeploymentTarget(ctx, tenantID, plan.TargetID)
	if err != nil {
		return corestore.CertificateReprotectionCutover{}, err
	}
	if !target.Enabled || target.Type != plan.Connector || target.RevisionID != plan.TargetRevisionID ||
		!sameHostTargetConfig(target.Config, intent.TargetConfig) {
		return corestore.CertificateReprotectionCutover{}, ErrCredentialPlanTargetChanged
	}
	cert, err := st.GetCertificateByFingerprint(ctx, tenantID, newFingerprint)
	if err != nil {
		return corestore.CertificateReprotectionCutover{}, err
	}
	if cert.Status != "active" || cert.KeyOrigin != "host_agent" ||
		cert.IssuanceIdempotencyKey == "" ||
		!strings.HasPrefix(cert.IssuanceIdempotencyKey, fmt.Sprintf("agentcsr:%d:0:", jobID)) {
		return corestore.CertificateReprotectionCutover{}, ErrCredentialPlanTargetChanged
	}
	info, err := certinfo.Inspect(cert.CertificateDER)
	if err != nil || info.IsCA || info.SHA256Fingerprint != newFingerprint ||
		info.SPKISHA256 != plan.PredecessorSPKISHA256 || info.CommonName != intent.SubjectCommonName ||
		!sameHostIdentifiers(info.DNSNames, intent.SubjectDNSNames) || len(info.IPAddresses) != 0 ||
		len(info.EmailAddresses) != 0 || len(info.URIs) != 0 {
		return corestore.CertificateReprotectionCutover{}, ErrCredentialPlanTargetChanged
	}
	successor, err := st.GetCAAuthority(ctx, tenantID, plan.SuccessorAuthorityID)
	if err != nil {
		return corestore.CertificateReprotectionCutover{}, err
	}
	caDER, err := certinfo.LeafDER([]byte(successor.CertificatePEM))
	if err != nil || crypto.VerifyLeafSignedByCA(cert.CertificateDER, caDER) != nil {
		return corestore.CertificateReprotectionCutover{}, ErrCredentialPlanTargetChanged
	}
	return corestore.CertificateReprotectionCutover{
		IdentityID: plan.IdentityID, TargetID: plan.TargetID,
		OldCertificateID: old.ID, OldFingerprint: old.Fingerprint,
		NewCertificateID: cert.ID, NewFingerprint: cert.Fingerprint,
		OldAuthorityID: plan.Job.KeyID, NewAuthorityID: plan.SuccessorAuthorityID,
		JobID: plan.Job.ID, ReceiptID: fmt.Sprintf("agent-job:%d:%d:verified", jobID, attempt),
	}, nil
}
