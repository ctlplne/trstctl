// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/cloudentitlements/assessment"
	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
	"trstctl.com/trstctl/internal/cloudentitlements/awspolicy"
	"trstctl.com/trstctl/internal/cloudentitlements/change"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func (s *Server) ProposeCloudMachineChange(ctx context.Context, tenantID, id, requester string, req api.CloudMachineChangeRequest) (change.Record, error) {
	finding, err := s.store.GetDiscoveryFinding(ctx, tenantID, req.FindingID)
	if err != nil {
		return change.Record{}, err
	}
	source, err := s.store.GetDiscoverySource(ctx, tenantID, finding.SourceID)
	if err != nil {
		return change.Record{}, err
	}
	run, err := s.store.GetDiscoveryRun(ctx, tenantID, finding.RunID)
	if err != nil {
		return change.Record{}, err
	}
	if source.Kind != assessment.SourceKind || finding.Kind != assessment.FindingKind || run.SourceID != source.ID || run.DryRun || (run.Status != "succeeded" && run.Status != "partial") {
		return change.Record{}, errors.New("cloud changes require a verified native discovery finding")
	}
	value, err := assessment.DecodeAssessment(finding.Metadata)
	if err != nil {
		return change.Record{}, err
	}
	fingerprint, err := assessment.Fingerprint(value)
	if err != nil || fingerprint != finding.Fingerprint {
		return change.Record{}, errors.New("captured cloud evidence fingerprint differs")
	}
	cfg, err := assessment.DecodeSource(source.Config)
	if err != nil {
		return change.Record{}, err
	}
	sourceFingerprint, err := assessment.SourceFingerprint(cfg)
	if err != nil {
		return change.Record{}, err
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://iam.amazonaws.com"
	}
	if value.SourceOrigin != endpoint || value.SourceFingerprint != sourceFingerprint || value.Identity.NativeID == "" || finding.DiscoveredAt.Before(time.Now().Add(-24*time.Hour)) {
		return change.Record{}, errors.New("rescan this exact native source before proposing a cloud change")
	}
	principal := value.Identity.Principal
	intent := change.Intent{RequiredApprovals: req.RequiredApprovals, Action: req.Action, SourceID: source.ID, FindingID: finding.ID, FindingFingerprint: fingerprint, SourceFingerprint: sourceFingerprint, PrincipalARN: principal.ARN, PrincipalID: value.Identity.NativeID, PrincipalKind: string(principal.Kind), PrincipalName: value.Identity.Name, Endpoint: endpoint, Region: cfg.Region, CAPEM: cfg.CAPEM, AllowPrivateEndpoint: cfg.AllowPrivateEndpoint, PrivateEgressCIDRs: append([]string(nil), cfg.PrivateEgressCIDRs...), WriterSessionFileRef: req.WriterSessionFileRef, Reason: req.Reason}
	switch req.Action {
	case change.RevokeKey:
		if principal.Kind != awspolicy.IAMUser || req.AccessKeyID == "" {
			return change.Record{}, errors.New("key revocation requires one captured IAM user key")
		}
		found := false
		for _, key := range value.Identity.Keys {
			if key.ID == req.AccessKeyID {
				found = true
			}
		}
		if !found {
			return change.Record{}, errors.New("access_key_id is not part of this captured native identity")
		}
		intent.AccessKeyID = req.AccessKeyID
	case change.TightenPolicy:
		document, digest, err := change.RestrictivePolicy(value, req.EvaluationIndex)
		if err != nil {
			return change.Record{}, err
		}
		intent.PolicyDocument = document
		intent.PolicySHA256 = digest
		intent.PolicyName = "trstctl-tighten-" + strings.ReplaceAll(id, "-", "")
	default:
		return change.Record{}, errors.New("unsupported cloud machine action")
	}
	if existing, err := s.store.GetCloudMachineChange(ctx, tenantID, id); err == nil {
		before, _ := change.Digest(existing.Intent)
		after, _ := change.Digest(intent)
		if before != after || existing.RequestedBy != requester {
			return change.Record{}, store.ErrIdempotencyConflict
		}
		existing.State = change.AwaitingApproval
		existing.UpdatedAt = existing.CreatedAt
		existing.Result = nil
		return existing, nil
	} else if !store.IsNotFound(err) {
		return change.Record{}, err
	}
	return s.orch.ProposeCloudMachineChange(ctx, tenantID, id, requester, intent, req.RequiredApprovals)
}
func (s *Server) ExecuteCloudMachineChange(ctx context.Context, tenantID, id, requester string) (change.Record, error) {
	return s.orch.ExecuteCloudMachineChange(ctx, tenantID, id, requester)
}
func (d *issuanceDispatcher) handleCloudMachineChange(ctx context.Context, message orchestrator.Message) error {
	var command struct {
		ID string `json:"id"`
	}
	if err := decodeCloudChangeCommand(message.Payload, &command); err != nil {
		return orchestrator.DefiniteNoEffect(err)
	}
	value, err := d.store.GetCloudMachineChange(ctx, message.TenantID, command.ID)
	if err != nil {
		return err
	}
	if value.State == change.Verified || value.State == change.Failed {
		return nil
	}
	if value.State != change.Queued {
		return orchestrator.DefiniteNoEffect(errors.New("cloud change is not queued"))
	}
	if recovered, err := d.orch.RecoverCloudMachineChangeResult(ctx, message.TenantID, value.ID); err != nil || recovered {
		return err
	}
	result := change.Result{CheckedAt: time.Now().UTC()}
	fail := func(err error) error {
		result.Error = err.Error()
		return d.orch.RecordCloudMachineChangeResult(ctx, message.TenantID, value.ID, change.Failed, result)
	}
	if !time.Now().Before(value.ExpiresAt) {
		return fail(errors.New("cloud change execution deadline expired"))
	}
	source, err := d.store.GetDiscoverySource(ctx, message.TenantID, value.Intent.SourceID)
	if err != nil {
		return fail(err)
	}
	cfg, err := assessment.DecodeSource(source.Config)
	if err != nil {
		return fail(err)
	}
	sourceFingerprint, err := assessment.SourceFingerprint(cfg)
	if err != nil || sourceFingerprint != value.Intent.SourceFingerprint {
		return fail(errors.New("approved native source settings drifted"))
	}
	finding, err := d.store.GetDiscoveryFinding(ctx, message.TenantID, value.Intent.FindingID)
	if err != nil || finding.Fingerprint != value.Intent.FindingFingerprint {
		return fail(errors.New("approved native finding is unavailable or drifted"))
	}
	if err := d.egress.CheckURL(value.Intent.Endpoint); err != nil {
		return fail(err)
	}
	ref, ok := strings.CutPrefix(value.Intent.WriterSessionFileRef, "env:")
	if !ok {
		return fail(errors.New("writer reference is not an approved env binding"))
	}
	path, present := os.LookupEnv(ref)
	if !present || !filepath.IsAbs(path) {
		return fail(errors.New("writer STS session file is not configured"))
	}
	prefixes := make([]netip.Prefix, 0, len(value.Intent.PrivateEgressCIDRs))
	for _, raw := range value.Intent.PrivateEgressCIDRs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return fail(errors.New("approved private egress prefix is invalid"))
		}
		prefixes = append(prefixes, prefix)
	}
	client, err := awsiam.NewChangeClient(awsiam.Config{Endpoint: value.Intent.Endpoint, Region: value.Intent.Region, CAPEM: []byte(value.Intent.CAPEM), AllowInsecureLoopback: value.Intent.AllowPrivateEndpoint, PrivateEgressCIDRs: prefixes, UseCredentials: awsiam.SessionFile(path, time.Now)})
	if err != nil {
		return fail(err)
	}
	target := awsiam.ChangeTarget{ARN: value.Intent.PrincipalARN, NativeID: value.Intent.PrincipalID, Name: value.Intent.PrincipalName, Kind: awspolicy.PrincipalKind(value.Intent.PrincipalKind)}
	var readback awsiam.ChangeReadback
	switch value.Intent.Action {
	case change.RevokeKey:
		readback, err = client.RevokeKey(ctx, target, value.Intent.AccessKeyID)
	case change.TightenPolicy:
		readback, err = client.PutOwnedDeny(ctx, target, value.Intent.PolicyName, value.Intent.PolicyDocument)
	default:
		err = errors.New("unsupported approved cloud action")
	}
	if err != nil {
		result.EffectUncertain = true
		return fail(err)
	}
	result = change.Result{KeyAbsent: readback.KeyAbsent, PolicyMatches: readback.PolicyMatches, Postcondition: readback.Postcondition, CheckedAt: readback.CheckedAt}
	return d.orch.RecordCloudMachineChangeResult(ctx, message.TenantID, value.ID, change.Verified, result)
}

func decodeCloudChangeCommand(raw []byte, target any) error {
	if len(raw) > 4096 {
		return errors.New("cloud change command exceeds bound")
	}
	return json.Unmarshal(raw, target)
}
