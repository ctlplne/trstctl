// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/migration"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// handleMigrationApplianceIssue is the control-plane half of an appliance
// member's successor (A33). A host member generates its own key and the host
// agent presents a CSR; an appliance cannot, so the control plane mints the
// successor under the run's authority with exactly the identifiers frozen in
// the member binding, records it as the predecessor's successor, binds its
// fingerprint to the run, and queues the sealed deploy for the exact network
// relay the member binds. The relay's signed verified receipt — the same D2
// handshake every appliance deploy ends with — closes the run's live gate.
//
// The row is idempotent on its outbox key: a retry after a crash reopens the
// retained subject key, reaches the same issuance, and re-queues nothing.
func (d *issuanceDispatcher) handleMigrationApplianceIssue(ctx context.Context, m orchestrator.Message) error {
	if d == nil || d.store == nil || d.orch == nil || d.outbox == nil || d.idem == nil {
		return errors.New("server: appliance migration issuance is not configured")
	}
	var intent orchestrator.MigrationApplianceIssueIntent
	if err := json.Unmarshal(m.Payload, &intent); err != nil {
		return fmt.Errorf("server: decode appliance migration intent: %w", err)
	}
	if strings.TrimSpace(intent.RunID) == "" || strings.TrimSpace(intent.WaveID) == "" || strings.TrimSpace(intent.IdentityID) == "" {
		return errors.New("server: appliance migration intent has incomplete identity")
	}
	record, err := d.store.GetMigrationRun(ctx, m.TenantID, intent.RunID)
	if err != nil {
		return err
	}
	run := record.Run
	member, found := migration.Member(run, intent.WaveID, intent.IdentityID)
	if !found || !member.Binding.OnAppliance() || member.Binding.TargetID != intent.TargetID ||
		member.Binding.RequiredAgentID != intent.RequiredAgentID ||
		member.Binding.PredecessorCertificateID != intent.PredecessorCertificateID {
		return orchestrator.DefiniteNoEffect(errors.New("server: appliance migration intent drifted from the immutable member binding"))
	}
	switch run.Status {
	case migration.RunPaused:
		return orchestrator.DeferDelivery(errors.New("server: migration is paused; the appliance successor waits for resume"))
	case migration.RunRunning:
	default:
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: migration is %s; no appliance successor is issued", run.Status))
	}
	if !migrationWaveAtLiveGate(run, intent.WaveID) || member.SuccessorVerdict != "" {
		return orchestrator.DefiniteNoEffect(errors.New("server: appliance successor is not licensed by the run's current gate"))
	}
	ident, err := d.store.GetIdentity(ctx, m.TenantID, intent.IdentityID)
	if err != nil {
		return err
	}
	if err := d.identityStillPermitsIssuance(ctx, m.TenantID, ident.ID); err != nil {
		return err
	}
	ctx = withLeafCommand(ctx, d.idem, m.TenantID, m.IdempotencyKey)
	_, err = d.idem.Do(ctx, m.TenantID, "migration-appliance-issue:"+m.IdempotencyKey, func(ctx context.Context) ([]byte, error) {
		return d.issueApplianceSuccessor(ctx, m, run, intent.WaveID, member, ident)
	})
	return err
}

func migrationWaveAtLiveGate(run migration.Run, waveID string) bool {
	for _, wave := range run.Waves {
		if wave.ID == waveID {
			return wave.Started && wave.Phase == migration.PhaseVerifyingLive
		}
	}
	return false
}

// issueApplianceSuccessor is the credential-bearing effect inside the durable
// idempotency boundary: mint, record, bind, queue.
func (d *issuanceDispatcher) issueApplianceSuccessor(
	ctx context.Context, m orchestrator.Message, run migration.Run, waveID string,
	member migration.RunMember, ident store.Identity,
) ([]byte, error) {
	b := member.Binding
	tmpl, err := migrationApplianceSubjectTemplate(b)
	if err != nil {
		return nil, err
	}
	issueKey := "migration-appliance:" + m.IdempotencyKey
	material, err := d.mintServedLeafMaterialFromTemplate(ctx, m.TenantID, ident.OwnerID, tmpl,
		endpointAuthoritySelection{Source: "private", ID: b.IssuingAuthorityID}, issueKey, migrationIssuanceBinding(b.Issuance))
	if err != nil {
		return nil, err
	}
	defer material.destroyKey()
	cert := material.Certificate
	cert.IssuanceIdempotencyKey = issueKey
	cert.CertificatePEM = append(append([]byte(nil), material.CertPEM...), material.ChainPEM...)
	recorded, err := d.orch.RecordSuccessorCertificate(ctx, m.TenantID, cert, b.PredecessorCertificateID)
	if err != nil {
		return nil, err
	}
	eventID := orchestrator.MigrationEventID(m.TenantID, run.ID, "issued:"+m.IdempotencyKey)
	if _, err := d.orch.UpdateMigrationRun(ctx, m.TenantID, run.ID, eventID,
		func(current migration.Run) (migration.Run, []migration.Action, error) {
			next, err := migration.RecordSuccessorIssued(current, waveID, member.IdentityID, recorded.Fingerprint)
			return next, nil, err
		}); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(connector.DeployPayload{
		IdentityID: member.IdentityID, TargetID: b.TargetID, TargetRevision: b.TargetRevision,
		Connector: b.Connector, Target: b.Target, TargetConfig: append(json.RawMessage(nil), b.TargetConfig...),
		CertPEM: cert.CertificatePEM, KeyPEM: material.KeyPEM, Fingerprint: recorded.Fingerprint,
		MigrationRunID: run.ID, MigrationWaveID: waveID, RequiredAgentID: b.RequiredAgentID,
	})
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(payload)
	idemKey := "migration:" + run.ID + ":" + waveID + ":" + member.IdentityID + ":appliance_deploy"
	sealed, err := d.sealConnectorDeployBytes(ctx, m.TenantID, "connector.deploy", idemKey, payload)
	if err != nil {
		return nil, err
	}
	if err := d.store.WithTenant(ctx, m.TenantID, func(tx pgx.Tx) error {
		_, err := d.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
			TenantID: m.TenantID, Destination: "connector.deploy", IdempotencyKey: idemKey, Payload: sealed,
			EffectLane:        "migration:identity:" + member.IdentityID,
			RequiredAgentRole: mtls.AgentRoleNetwork, RequiredAgentID: b.RequiredAgentID,
		})
		return err
	}); err != nil {
		return nil, err
	}
	return []byte(recorded.Fingerprint), nil
}

// migrationApplianceSubjectTemplate turns the frozen identifier halves of the
// member binding into the successor's request: every identifier the
// predecessor carried, and no other.
func migrationApplianceSubjectTemplate(b migration.MemberBinding) (crypto.CertificateRequestTemplate, error) {
	tmpl := crypto.CertificateRequestTemplate{
		CommonName: b.SubjectCommonName, DNSNames: append([]string(nil), b.SubjectDNSNames...),
		EmailAddresses: append([]string(nil), b.SubjectEmailAddresses...), URIs: append([]string(nil), b.SubjectURIs...),
	}
	for _, address := range b.SubjectIPAddresses {
		ip := net.ParseIP(strings.TrimSpace(address))
		if ip == nil {
			return crypto.CertificateRequestTemplate{}, fmt.Errorf("server: migration member binding carries an unparsable IP address %q", address)
		}
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}
	if tmpl.CommonName == "" || (len(tmpl.DNSNames) == 0 && len(tmpl.IPAddresses) == 0 && len(tmpl.EmailAddresses) == 0 && len(tmpl.URIs) == 0) {
		return crypto.CertificateRequestTemplate{}, errors.New("server: migration member binding has no subject to certify")
	}
	return tmpl, nil
}

// migrationIssuanceBinding converts the run's frozen profile binding to the
// store's wire-identical shape the profile gate consumes; nil stays nil.
func migrationIssuanceBinding(in *migration.IssuanceBinding) *store.OperationApprovalIssuanceBinding {
	if in == nil {
		return nil
	}
	return &store.OperationApprovalIssuanceBinding{
		ProfileName: in.ProfileName, ProfileID: in.ProfileID, ProfileVersion: in.ProfileVersion,
		ProfileSpecDigest: in.ProfileSpecDigest, RequestedTTLSeconds: in.RequestedTTLSeconds,
		EffectiveTTLSeconds: in.EffectiveTTLSeconds,
	}
}
