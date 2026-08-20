// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/events"
	sshca "trstctl.com/trstctl/internal/protocols/ssh"
)

const (
	eventSSHTrustRolloutRecorded = "ssh.trust_rollout.recorded"
	eventSSHCertRevoked          = "ssh.cert.revoked"
	eventSSHHostRetired          = "ssh.host.retired"
)

func (s *Server) SSHStatus(ctx context.Context, tenantID string) (api.SSHStatus, error) {
	sp, err := s.sshWorkflowProtocol(tenantID)
	if err != nil {
		return api.SSHStatus{}, err
	}
	key, err := sp.AuthorityKey()
	if err != nil {
		return api.SSHStatus{}, fmt.Errorf("%w: authority key unavailable: %v", api.ErrSSHWorkflowUnavailable, err)
	}
	attestors, err := s.sshWorkflowAttestorMethods(ctx, tenantID)
	if err != nil {
		return api.SSHStatus{}, fmt.Errorf("%w: list attester trust sources: %v", api.ErrSSHWorkflowUnavailable, err)
	}
	return api.SSHStatus{
		Served:       true,
		TenantID:     tenantID,
		AuthorityKey: string(key),
		KRLVersion:   sp.KRLVersion(),
		RevokedCount: sp.RevokedCount(),
		Attestors:    attestors,
	}, nil
}

func (s *Server) RecordSSHTrustRollout(ctx context.Context, tenantID, idempotencyKey string, req api.SSHTrustRolloutRequest) (api.SSHTrustRollout, error) {
	if _, err := s.sshWorkflowProtocol(tenantID); err != nil {
		return api.SSHTrustRollout{}, err
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return api.SSHTrustRollout{}, fmt.Errorf("%w: idempotency key is required", api.ErrSSHWorkflowInvalid)
	}
	status := strings.TrimSpace(req.Status)
	if status == "" {
		status = "planned"
	}
	if !validSSHTrustRolloutStatus(status) {
		return api.SSHTrustRollout{}, fmt.Errorf("%w: invalid rollout status %q", api.ErrSSHWorkflowInvalid, status)
	}
	hosts := compactStrings(req.TargetHosts)
	if len(hosts) == 0 {
		return api.SSHTrustRollout{}, fmt.Errorf("%w: target_hosts is required", api.ErrSSHWorkflowInvalid)
	}
	requiredEvidence := []struct {
		name  string
		value string
	}{
		{name: "candidate_ca_fingerprint", value: req.CandidateCAFingerprint},
		{name: "reload_command", value: req.ReloadCommand},
		{name: "health_command", value: req.HealthCommand},
		{name: "rollback_plan", value: req.RollbackPlan},
	}
	for _, field := range requiredEvidence {
		if strings.TrimSpace(field.value) == "" {
			return api.SSHTrustRollout{}, fmt.Errorf("%w: %s is required", api.ErrSSHWorkflowInvalid, field.name)
		}
	}
	if !req.Confirmed {
		return api.SSHTrustRollout{}, fmt.Errorf("%w: confirmed must be true for SSH trust rollout evidence", api.ErrSSHWorkflowRejected)
	}
	now := time.Now().UTC()
	out := api.SSHTrustRollout{
		TenantID: tenantID, SourceID: strings.TrimSpace(req.SourceID), TargetHosts: hosts,
		CandidateCAFingerprint: strings.TrimSpace(req.CandidateCAFingerprint),
		ReloadCommand:          strings.TrimSpace(req.ReloadCommand),
		HealthCommand:          strings.TrimSpace(req.HealthCommand),
		RollbackPlan:           strings.TrimSpace(req.RollbackPlan),
		Status:                 status, Confirmed: req.Confirmed, RecordedAt: now,
	}
	data, _ := json.Marshal(out)
	ev, err := s.appendSSHWorkflowEvent(ctx, tenantID, eventSSHTrustRolloutRecorded, data)
	if err != nil {
		return api.SSHTrustRollout{}, err
	}
	out.ID = ev.ID
	return out, nil
}

func (s *Server) IssueAttestedSSHUserCert(ctx context.Context, tenantID, idempotencyKey string, req api.SSHAttestedUserCertRequest) (api.SSHAttestedUserCert, error) {
	sp, err := s.sshWorkflowProtocol(tenantID)
	if err != nil {
		return api.SSHAttestedUserCert{}, err
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return api.SSHAttestedUserCert{}, fmt.Errorf("%w: idempotency key is required", api.ErrSSHWorkflowInvalid)
	}
	method := strings.TrimSpace(req.Method)
	if method == "" {
		return api.SSHAttestedUserCert{}, fmt.Errorf("%w: method is required", api.ErrSSHWorkflowInvalid)
	}
	if s.attestedIssuance == nil {
		return api.SSHAttestedUserCert{}, fmt.Errorf("%w: attestors are not configured", api.ErrSSHWorkflowUnavailable)
	}
	attestors, err := s.attestedIssuance.attestorsForMethod(ctx, tenantID, method)
	if err != nil {
		return api.SSHAttestedUserCert{}, fmt.Errorf("%w: list attester trust sources: %v", api.ErrSSHWorkflowInvalid, err)
	}
	if len(attestors) == 0 {
		return api.SSHAttestedUserCert{}, fmt.Errorf("%w: no enabled trust source for attestation method %q", api.ErrSSHWorkflowInvalid, method)
	}
	if strings.TrimSpace(req.PublicKey) == "" {
		return api.SSHAttestedUserCert{}, fmt.Errorf("%w: public_key is required", api.ErrSSHWorkflowInvalid)
	}
	approver := strings.TrimSpace(req.Approver)
	if approver == "" {
		return api.SSHAttestedUserCert{}, fmt.Errorf("%w: approver is required", api.ErrSSHWorkflowInvalid)
	}
	principals := compactStrings(req.Principals)
	sourceAddresses := compactStrings(req.SourceAddresses)
	forceCommand := strings.TrimSpace(req.ForceCommand)
	criticalOptions := map[string]string{}
	if len(sourceAddresses) > 0 {
		criticalOptions["source-address"] = strings.Join(sourceAddresses, ",")
	}
	if forceCommand != "" {
		criticalOptions["force-command"] = forceCommand
	}
	verifier, err := attest.NewVerifier(attest.Config{
		TenantID:  tenantID,
		Attestors: attestors,
		Audit:     attestedIssuanceAuditor(s.eventLogForSSHWorkflow()),
	})
	if err != nil {
		return api.SSHAttestedUserCert{}, fmt.Errorf("%w: verifier is invalid: %v", api.ErrSSHWorkflowInvalid, err)
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	if ttl > time.Hour {
		ttl = time.Hour
	}
	issuer, err := sshca.NewAttestedUserCertIssuer(sshca.AttestedConfig{
		TenantID: tenantID,
		CA:       sp.CA(),
		Verifier: verifier,
		Profile: sshca.Profile{
			Name:           "served-ssh-attested",
			MaxTTL:         time.Hour,
			AllowUserCerts: true,
			DefaultExtensions: map[string]string{
				"permit-pty": "",
			},
		},
		TTL:   ttl,
		Audit: attestedIssuanceAuditor(s.eventLogForSSHWorkflow()),
	})
	if err != nil {
		return api.SSHAttestedUserCert{}, fmt.Errorf("%w: %v", api.ErrSSHWorkflowInvalid, err)
	}
	issued, att, err := issuer.Issue(ctx, sshca.AttestedRequest{
		Method:           method,
		Payload:          req.Payload,
		SubjectPublicKey: []byte(req.PublicKey),
		KeyID:            strings.TrimSpace(req.KeyID),
		Approver:         approver,
		Principals:       principals,
		CriticalOptions:  criticalOptions,
	})
	if err != nil {
		return api.SSHAttestedUserCert{}, fmt.Errorf("%w: %v", api.ErrSSHWorkflowRejected, err)
	}
	responsePrincipals := principals
	if len(responsePrincipals) == 0 {
		responsePrincipals = []string{att.Subject}
	}
	return api.SSHAttestedUserCert{
		Certificate:     string(issued.Certificate),
		Serial:          issued.Serial,
		KeyID:           issued.KeyID,
		Subject:         att.Subject,
		Principals:      responsePrincipals,
		ValidBefore:     issued.ValidBefore.UTC().Format(time.RFC3339),
		Approver:        approver,
		SourceAddresses: sourceAddresses,
		ForceCommand:    forceCommand,
		Attestation:     att,
	}, nil
}

func (s *Server) RevokeSSHCertificate(ctx context.Context, tenantID, idempotencyKey string, req api.SSHRevokeCertificateRequest) (api.SSHStatus, error) {
	sp, err := s.sshWorkflowProtocol(tenantID)
	if err != nil {
		return api.SSHStatus{}, err
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return api.SSHStatus{}, fmt.Errorf("%w: idempotency key is required", api.ErrSSHWorkflowInvalid)
	}
	if req.Serial == 0 && strings.TrimSpace(req.KeyID) == "" {
		return api.SSHStatus{}, fmt.Errorf("%w: serial or key_id is required", api.ErrSSHWorkflowInvalid)
	}
	data, _ := json.Marshal(req)
	if _, err := s.appendSSHWorkflowEvent(ctx, tenantID, eventSSHCertRevoked, data); err != nil {
		return api.SSHStatus{}, err
	}
	sp.Revoke(req.Serial, strings.TrimSpace(req.KeyID))
	return s.SSHStatus(ctx, tenantID)
}

func (s *Server) RetireSSHHost(ctx context.Context, tenantID, idempotencyKey string, req api.SSHHostRetireRequest) (api.SSHHostRetirement, error) {
	if _, err := s.sshWorkflowProtocol(tenantID); err != nil {
		return api.SSHHostRetirement{}, err
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return api.SSHHostRetirement{}, fmt.Errorf("%w: idempotency key is required", api.ErrSSHWorkflowInvalid)
	}
	host := strings.TrimSpace(req.Host)
	if host == "" {
		return api.SSHHostRetirement{}, fmt.Errorf("%w: host is required", api.ErrSSHWorkflowInvalid)
	}
	out := api.SSHHostRetirement{
		TenantID: tenantID, Host: host, SourceID: strings.TrimSpace(req.SourceID),
		RunID: strings.TrimSpace(req.RunID), IdentityID: strings.TrimSpace(req.IdentityID),
		Reason: strings.TrimSpace(req.Reason), Status: "retired", RecordedAt: time.Now().UTC(),
	}
	data, _ := json.Marshal(out)
	ev, err := s.appendSSHWorkflowEvent(ctx, tenantID, eventSSHHostRetired, data)
	if err != nil {
		return api.SSHHostRetirement{}, err
	}
	out.ID = ev.ID
	return out, nil
}

func (s *Server) sshWorkflowProtocol(tenantID string) (*sshProtocol, error) {
	if s.protocols == nil || s.protocols.ssh == nil {
		return nil, api.ErrSSHWorkflowUnavailable
	}
	if tenantID == "" || tenantID != s.protocols.ssh.tenantID {
		return nil, fmt.Errorf("%w: tenant is not bound to the served SSH protocol", api.ErrSSHWorkflowRejected)
	}
	return s.protocols.ssh, nil
}

func (s *Server) appendSSHWorkflowEvent(ctx context.Context, tenantID, typ string, data []byte) (events.Event, error) {
	if s == nil || s.log == nil {
		return events.Event{}, fmt.Errorf("%w: event log is unavailable", api.ErrSSHWorkflowUnavailable)
	}
	return s.log.Append(ctx, events.Event{Type: typ, TenantID: tenantID, Data: data})
}

func (s *Server) eventLogForSSHWorkflow() *events.Log {
	if s == nil {
		return nil
	}
	return s.log
}

func (s *Server) sshWorkflowAttestorMethods(ctx context.Context, tenantID string) ([]string, error) {
	if s == nil || s.attestedIssuance == nil {
		return nil, nil
	}
	methods := make(map[string]struct{}, len(s.attestedIssuance.attestors))
	for _, a := range s.attestedIssuance.attestors {
		if a != nil && a.Method() != "" {
			methods[a.Method()] = struct{}{}
		}
	}
	if s.attestedIssuance.store != nil {
		sources, err := s.attestedIssuance.store.ListWorkloadAttesterTrustSources(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		for _, source := range sources {
			if source.Enabled && strings.TrimSpace(source.Method) != "" {
				methods[source.Method] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(methods))
	for method := range methods {
		out = append(out, method)
	}
	sort.Strings(out)
	return out, nil
}

func validSSHTrustRolloutStatus(status string) bool {
	switch status {
	case "planned", "validating", "health_passed", "rolled_back", "failed":
		return true
	default:
		return false
	}
}

func compactStrings(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// SSHFleetInventory answers B-2: which hosts still carry standing SSH key
// access. Every ssh_keys row is a raw key — a CA-minted certificate is not
// stored there — so this view IS the not-under-CA list, and the API layer
// says so explicitly rather than leaving the reader to infer it.
func (s *Server) SSHFleetInventory(ctx context.Context, tenantID string) ([]api.SSHFleetHost, error) {
	if s.store == nil {
		return nil, nil
	}
	hosts, err := s.store.SSHFleetInventory(ctx, tenantID, 0)
	if err != nil {
		return nil, err
	}
	out := make([]api.SSHFleetHost, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, api.SSHFleetHost{
			Location: host.Location, Keys: host.Keys,
			StandingKeys: host.StandingKeys, OrphanedKeys: host.OrphanedKeys,
			KeyTypes: host.KeyTypes, Sources: host.Sources,
			FirstObserved: host.FirstObserved, LastObserved: host.LastObserved,
		})
	}
	return out, nil
}
