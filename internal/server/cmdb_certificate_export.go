// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/cmdbexport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/secrettext"
)

var cmdbExportNamespace = uuid.MustParse("9b1770bd-c1a6-52db-927d-389e219e315a")

type certificateCIExporter struct {
	server      *Server
	bindings    map[string]config.CMDBCertificateExportBinding
	credentials integrationCredentialResolver
	clientFor   func(config.CMDBCertificateExportBinding) (*http.Client, error)
}

func (s *Server) configureCMDBCertificateExports(d Deps) error {
	if errs := config.ValidateCMDBCertificateExports(d.CMDBCertificateExports); len(errs) > 0 {
		return errors.Join(errs...)
	}
	exporter := &certificateCIExporter{server: s, bindings: map[string]config.CMDBCertificateExportBinding{}, credentials: integrationCredentialResolver{store: d.Store, kek: d.KEK, crypto: d.TenantCrypto}}
	for _, binding := range d.CMDBCertificateExports {
		id, _ := uuid.Parse(binding.TenantID)
		binding.TenantID = id.String()
		binding.PrivateEgressCIDRs = append([]string(nil), binding.PrivateEgressCIDRs...)
		exporter.bindings[binding.TenantID+":"+binding.ID] = binding
	}
	exporter.clientFor = func(binding config.CMDBCertificateExportBinding) (*http.Client, error) {
		client, err := cloudHTTPClient(binding.InstanceURL, binding.AllowPrivateEndpoint, binding.PrivateEgressCIDRs)
		if err != nil {
			return nil, err
		}
		if d.EgressGuard.Enabled() {
			client.Transport = d.EgressGuard.WrapTransport(client.Transport)
		}
		return client, nil
	}
	s.cmdbExports = exporter
	return nil
}

func (s *certificateCIExporter) Bindings(tenantID string) []api.CMDBExportBinding {
	out := []api.CMDBExportBinding{}
	for _, binding := range s.bindings {
		if binding.TenantID == tenantID {
			out = append(out, api.CMDBExportBinding{ID: binding.ID, Enabled: binding.Enabled, DataSource: binding.DataSource})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func cmdbBindingDigest(binding config.CMDBCertificateExportBinding) string {
	encoded, _ := json.Marshal(binding)
	return "sha256:" + crypto.SHA256Hex(encoded)
}

func (s *certificateCIExporter) Queue(ctx context.Context, tenantID, key string, input api.CMDBExportInput) (api.CMDBExportStatus, error) {
	if strings.TrimSpace(key) == "" {
		return api.CMDBExportStatus{}, fmt.Errorf("%w: idempotency key is required", api.ErrCMDBExportInvalid)
	}
	certificateID, err := uuid.Parse(input.CertificateID)
	if err != nil || certificateID == uuid.Nil {
		return api.CMDBExportStatus{}, fmt.Errorf("%w: certificate_id must be an inventory UUID", api.ErrCMDBExportInvalid)
	}
	input.CertificateID = certificateID.String()

	binding, ok := s.bindings[tenantID+":"+input.BindingID]
	if !ok || !binding.Enabled {
		return api.CMDBExportStatus{}, fmt.Errorf("%w: an enabled operator-owned certificate write binding is required", api.ErrCMDBExportInvalid)
	}
	cert, err := s.server.store.GetCertificate(ctx, tenantID, input.CertificateID)
	if err != nil {
		return api.CMDBExportStatus{}, err
	}
	if len(cert.CertificateDER) == 0 && len(cert.CertificatePEM) == 0 {
		return api.CMDBExportStatus{}, fmt.Errorf("%w: recover this certificate's DER before exporting its CI", api.ErrCMDBExportInvalid)
	}
	id := uuid.NewSHA1(cmdbExportNamespace, []byte(tenantID+"\x00"+key)).String()
	command := cmdbexport.Command{ID: id, CertificateID: cert.ID, Fingerprint: cert.Fingerprint, BindingID: binding.ID, BindingDigest: cmdbBindingDigest(binding)}
	if actor, ok := events.ActorFromContext(ctx); ok {
		command.RequestedBy = actor.Subject
	}
	if err := s.server.orch.RequestCMDBCertificateExport(ctx, tenantID, command); err != nil {
		return api.CMDBExportStatus{}, err
	}
	return s.Status(ctx, tenantID, id)
}

func cmdbReceiptID(id string) string {
	return uuid.NewSHA1(cmdbExportNamespace, []byte("verified:"+id)).String()
}

func (s *certificateCIExporter) Status(ctx context.Context, tenantID, id string) (api.CMDBExportStatus, error) {
	parsedID, err := uuid.Parse(id)
	if err != nil || parsedID == uuid.Nil {
		return api.CMDBExportStatus{}, pgx.ErrNoRows
	}
	id = parsedID.String()
	event, found, err := s.server.log.EventByID(ctx, id)
	if err != nil {
		return api.CMDBExportStatus{}, err
	}
	if !found || event.TenantID != tenantID || event.Type != cmdbexport.EventRequested {
		return api.CMDBExportStatus{}, pgx.ErrNoRows
	}
	var command cmdbexport.Command
	if err := json.Unmarshal(event.Data, &command); err != nil {
		return api.CMDBExportStatus{}, err
	}
	if err := command.Validate(); err != nil {
		return api.CMDBExportStatus{}, err
	}
	if command.ID != id {
		return api.CMDBExportStatus{}, errors.New("CMDB export source identity differs")
	}
	out := api.CMDBExportStatus{ID: id, BindingID: command.BindingID, CertificateID: command.CertificateID, Fingerprint: command.Fingerprint, Status: "queued"}
	receipt, found, err := s.receipt(ctx, tenantID, command)
	if err != nil {
		return out, err
	}
	if found {
		out.Status = "verified"
		out.Receipt = &receipt
		out.VerifiedAt = &receipt.CheckedAt
		return out, nil
	}
	attempt, err := s.server.store.GetOutboxAttemptByKey(ctx, tenantID, cmdbexport.Destination, id)
	if errors.Is(err, pgx.ErrNoRows) {
		out.Status = "recovery_required"
		out.LastError = "The retained command has no queue row or verified receipt; restart reconciliation restores its intent."
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Status = attempt.Status
	out.Attempts = attempt.Attempts
	if attempt.LastError != "" {
		out.LastError = "Certificate CI export has not been independently verified; inspect the CMDB binding, credential, IRE rules and readback permissions."
	}
	if out.Status == "delivered" {
		return out, errors.New("CMDB export queue completed without a bound verification receipt")
	}
	return out, nil
}

func (s *certificateCIExporter) receipt(ctx context.Context, tenantID string, command cmdbexport.Command) (cmdbexport.Receipt, bool, error) {
	event, found, err := s.server.log.EventByID(ctx, cmdbReceiptID(command.ID))
	if err != nil || !found {
		return cmdbexport.Receipt{}, found, err
	}
	var receipt cmdbexport.Receipt
	if event.Type != cmdbexport.EventVerified || event.TenantID != tenantID || event.SchemaVersion != 1 {
		return receipt, false, errors.New("CMDB export verification envelope differs")
	}
	if err := json.Unmarshal(event.Data, &receipt); err != nil {
		return receipt, false, err
	}
	if receipt.OperationID != command.ID || receipt.BindingID != command.BindingID || receipt.BindingDigest != command.BindingDigest || receipt.CertificateID != command.CertificateID || receipt.Fingerprint != command.Fingerprint || receipt.CheckedAt.IsZero() || receipt.SystemID == "" || receipt.ValuesDigest == "" {
		return receipt, false, errors.New("CMDB export verification receipt differs from its command")
	}
	return receipt, true, nil
}

func (s *certificateCIExporter) Deliver(ctx context.Context, message orchestrator.Message) error {
	var command cmdbexport.Command
	if err := json.Unmarshal(message.Payload, &command); err != nil {
		return orchestrator.DefiniteNoEffect(errors.New("invalid CMDB export command"))
	}
	if err := command.Validate(); err != nil {
		return orchestrator.DefiniteNoEffect(err)
	}
	if command.ID != message.IdempotencyKey {
		return orchestrator.DefiniteNoEffect(errors.New("CMDB export command id differs from its outbox key"))
	}
	source, found, err := s.server.log.EventByID(ctx, command.ID)
	if err != nil {
		return err
	}
	if !found || source.TenantID != message.TenantID || source.Type != cmdbexport.EventRequested || source.SchemaVersion != 1 || !bytes.Equal(source.Data, message.Payload) {
		return orchestrator.DefiniteNoEffect(errors.New("CMDB export outbox differs from its retained source"))
	}
	if _, found, err := s.receipt(ctx, message.TenantID, command); err != nil || found {
		return err
	}
	binding, ok := s.bindings[message.TenantID+":"+command.BindingID]
	if !ok || !binding.Enabled || cmdbBindingDigest(binding) != command.BindingDigest {
		return orchestrator.DefiniteNoEffect(errors.New("CMDB export binding was disabled, removed or changed; queue a new export under the current binding"))
	}
	cert, err := s.server.store.GetCertificate(ctx, message.TenantID, command.CertificateID)
	if err != nil {
		return orchestrator.DefiniteNoEffect(err)
	}
	if cert.Fingerprint != command.Fingerprint {
		return orchestrator.DefiniteNoEffect(errors.New("CMDB export certificate identity changed"))
	}
	material := cert.CertificateDER
	if len(material) == 0 {
		material = cert.CertificatePEM
	}
	info, err := certinfo.Inspect(material)
	if err != nil || info.SHA256Fingerprint != command.Fingerprint {
		return orchestrator.DefiniteNoEffect(errors.New("CMDB export needs verified certificate DER matching the inventory fingerprint"))
	}
	request, err := cmdbexport.Payload(message.TenantID, binding.DataSource, info, cert.Status, time.Now().UTC())
	if err != nil {
		return orchestrator.DefiniteNoEffect(err)
	}
	client, err := s.clientFor(binding)
	if err != nil {
		return orchestrator.DefiniteNoEffect(err)
	}
	credential, err := s.credentials.resolve(ctx, message.TenantID, binding.TokenRef)
	if err != nil {
		return orchestrator.DefiniteNoEffect(errors.New("CMDB write credential could not be resolved"))
	}
	defer credential.Destroy()
	endpoint, err := cmdbexport.Endpoint(binding.InstanceURL, binding.DataSource)
	if err != nil {
		return orchestrator.DefiniteNoEffect(err)
	}
	body, err := json.Marshal(request)
	if err != nil {
		return orchestrator.DefiniteNoEffect(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return orchestrator.DefiniteNoEffect(err)
	}
	req.Header.Set("Authorization", secrettext.Prefixed("Bearer ", credential.Bytes()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Idempotency-Key", command.ID)
	response, err := client.Do(req)
	if err != nil {
		return errors.New("CMDB certificate IRE request failed; outcome requires reconciliation")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("CMDB certificate IRE returned HTTP %d", response.StatusCode)
	}
	systemID, err := cmdbexport.ParseReceipt(response.Body)
	if err != nil {
		return err
	}
	readback, err := cmdbexport.ReadbackEndpoint(binding.InstanceURL, systemID, request.Items[0].Values)
	if err != nil {
		return err
	}
	get, err := http.NewRequestWithContext(ctx, http.MethodGet, readback, nil)
	if err != nil {
		return err
	}
	get.Header.Set("Authorization", secrettext.Prefixed("Bearer ", credential.Bytes()))
	get.Header.Set("Accept", "application/json")
	observed, err := client.Do(get)
	if err != nil {
		return errors.New("CMDB certificate independent read failed")
	}
	defer func() { _ = observed.Body.Close() }()
	if observed.StatusCode != http.StatusOK {
		return fmt.Errorf("CMDB certificate readback returned HTTP %d", observed.StatusCode)
	}
	if err := cmdbexport.VerifyReadback(observed.Body, systemID, request.Items[0].Values); err != nil {
		return err
	}
	current, err := s.server.store.GetCertificate(ctx, message.TenantID, command.CertificateID)
	if err != nil {
		return err
	}
	if current.Fingerprint != cert.Fingerprint || current.Status != cert.Status {
		return errors.New("certificate lifecycle changed during CMDB export; retry under the current state")
	}
	values, _ := json.Marshal(request.Items[0].Values)
	receipt := cmdbexport.Receipt{OperationID: command.ID, BindingID: command.BindingID, BindingDigest: command.BindingDigest, CertificateID: command.CertificateID, Fingerprint: command.Fingerprint, CertificateStatus: cert.Status, SystemID: systemID, ValuesDigest: "sha256:" + crypto.SHA256Hex(values), CheckedAt: time.Now().UTC()}
	return s.appendReceipt(ctx, message.TenantID, command, receipt)
}

var _ api.CMDBCertificateExports = (*certificateCIExporter)(nil)

func (d *issuanceDispatcher) handleCMDBCertificateExport(ctx context.Context, m orchestrator.Message) error {
	if d.cmdbExports == nil {
		return orchestrator.DefiniteNoEffect(errors.New("server: certificate CMDB export is not configured"))
	}
	return d.cmdbExports.Deliver(ctx, m)
}

func (s *certificateCIExporter) appendReceipt(ctx context.Context, tenantID string, command cmdbexport.Command, receipt cmdbexport.Receipt) error {
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	if _, err := s.server.log.Append(ctx, events.Event{ID: cmdbReceiptID(command.ID), Type: cmdbexport.EventVerified, TenantID: tenantID, Data: encoded}); err != nil {
		return err
	}
	canonical, found, err := s.receipt(ctx, tenantID, command)
	if err != nil {
		return err
	}
	if !found || canonical.ValuesDigest != receipt.ValuesDigest || canonical.CertificateStatus != receipt.CertificateStatus || canonical.SystemID != receipt.SystemID {
		return errors.New("CMDB export canonical receipt differs from the independently verified effect")
	}
	return nil
}
