// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/ctlog"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const (
	ctSubmissionCapability     = "CAP-REV-06"
	ctSubmissionDestination    = "ct.submit"
	ctSubmissionEventQueued    = "ct.submission.queued"
	ctSubmissionEventDelivered = "ct.submission.delivered"
	ctSubmissionPrecertificate = "precertificate"
	ctSubmissionCertificate    = "certificate"
	maxCTSubmissionResponse    = 1 << 20
)

var ctSubmissionNamespace = uuid.MustParse("720f26c9-9cf8-5d18-8d65-6bfb9cc1f9a4")

type servedCTSubmissionService struct {
	store  *store.Store
	log    *events.Log
	outbox *orchestrator.Outbox
	now    func() time.Time
}

func newServedCTSubmissionService(st *store.Store, log *events.Log, outbox *orchestrator.Outbox) (*servedCTSubmissionService, error) {
	if st == nil || log == nil || outbox == nil {
		return nil, errors.New("server: CT submission requires store, event log, and outbox")
	}
	return &servedCTSubmissionService{
		store: st, log: log, outbox: outbox,
		now: func() time.Time { return time.Now().UTC() },
	}, nil
}

func (s *servedCTSubmissionService) SubmitCertificateTransparency(ctx context.Context, tenantID, idempotencyKey string, req api.CTLogSubmissionRequest) (api.CTLogSubmissionResponse, error) {
	if strings.TrimSpace(idempotencyKey) == "" {
		return api.CTLogSubmissionResponse{}, errors.New("idempotency key is required")
	}
	logs := cleanedUnique(req.Logs)
	if len(logs) == 0 {
		return api.CTLogSubmissionResponse{}, errors.New("at least one Certificate Transparency log URL is required")
	}
	if !req.AllowPrivateEndpoint {
		for _, logURL := range logs {
			if err := netsec.ValidatePublicHTTPSURL(logURL); err != nil {
				return api.CTLogSubmissionResponse{}, fmt.Errorf("certificate transparency log %q rejected: %w", logURL, err)
			}
		}
	} else if _, err := privateEgressSafeClientOptions(req.PrivateEgressCIDRs); err != nil {
		return api.CTLogSubmissionResponse{}, err
	}
	logKeys, err := ctLogPublicKeys(req.LogPublicKeys, logs)
	if err != nil {
		return api.CTLogSubmissionResponse{}, err
	}
	certDER, certInfo, err := decodeCertificatePEMOrBase64(req.CertificatePEM, "certificate_pem")
	if err != nil {
		return api.CTLogSubmissionResponse{}, err
	}
	var precertDER []byte
	var precertInfo certinfo.Info
	precertPresent := strings.TrimSpace(req.PrecertificatePEM) != ""
	if precertPresent {
		precertDER, precertInfo, err = decodeCertificatePEMOrBase64(req.PrecertificatePEM, "precertificate_pem")
		if err != nil {
			return api.CTLogSubmissionResponse{}, err
		}
	}
	chainDER, err := decodeCertificateBundle(req.ChainPEM, "chain_pem")
	if err != nil {
		return api.CTLogSubmissionResponse{}, err
	}

	now := s.now()
	res := api.CTLogSubmissionResponse{Capability: ctSubmissionCapability}
	var payloads []ctSubmissionPayload
	var unkeyed []string
	for _, logURL := range logs {
		if logKeys[logURL] == nil {
			unkeyed = append(unkeyed, logURL)
		}
		logStatus := api.CTLogSubmissionLog{LogURL: logURL}
		if precertPresent {
			id := ctSubmissionID(tenantID, logURL, ctSubmissionPrecertificate, precertInfo.SHA256Fingerprint)
			payloads = append(payloads, ctSubmissionPayload{
				Capability:             ctSubmissionCapability,
				SubmissionID:           id,
				LogURL:                 logURL,
				EntryType:              ctSubmissionPrecertificate,
				LeafDER:                precertDER,
				ChainDER:               chainDER,
				LeafSHA256Fingerprint:  precertInfo.SHA256Fingerprint,
				Subject:                precertInfo.Subject,
				SerialNumber:           precertInfo.SerialNumber,
				RequestedBy:            req.RequestedBy,
				IdempotencyKey:         idempotencyKey,
				AllowPrivateEndpoint:   req.AllowPrivateEndpoint,
				PrivateEgressCIDRs:     append([]string(nil), req.PrivateEgressCIDRs...),
				SubmissionProfile:      req.SubmissionProfile,
				OperatorCorrelationRef: req.OperatorCorrelationRef,
				QueuedAt:               now,
				LogPublicKey:           logKeys[logURL],
				CertificateFingerprint: certInfo.SHA256Fingerprint,
			})
			logStatus.PrecertificateQueued = true
			logStatus.PrecertificateSubmissionID = id
			res.Queued++
		}
		id := ctSubmissionID(tenantID, logURL, ctSubmissionCertificate, certInfo.SHA256Fingerprint)
		payloads = append(payloads, ctSubmissionPayload{
			Capability:             ctSubmissionCapability,
			SubmissionID:           id,
			LogURL:                 logURL,
			EntryType:              ctSubmissionCertificate,
			LeafDER:                certDER,
			ChainDER:               chainDER,
			LeafSHA256Fingerprint:  certInfo.SHA256Fingerprint,
			Subject:                certInfo.Subject,
			SerialNumber:           certInfo.SerialNumber,
			RequestedBy:            req.RequestedBy,
			IdempotencyKey:         idempotencyKey,
			AllowPrivateEndpoint:   req.AllowPrivateEndpoint,
			PrivateEgressCIDRs:     append([]string(nil), req.PrivateEgressCIDRs...),
			SubmissionProfile:      req.SubmissionProfile,
			OperatorCorrelationRef: req.OperatorCorrelationRef,
			QueuedAt:               now,
			LogPublicKey:           logKeys[logURL],
			CertificateFingerprint: certInfo.SHA256Fingerprint,
		})
		logStatus.CertificateQueued = true
		logStatus.CertificateSubmissionID = id
		res.Queued++
		res.Logs = append(res.Logs, logStatus)
	}
	if len(unkeyed) > 0 {
		res.Residuals = append(res.Residuals, api.CTLogSubmissionNote{
			Code: "ct-log-key-not-named",
			Detail: "No public key was named for " + strings.Join(unkeyed, ", ") +
				"; trstctl keeps those logs' SCTs unverified and does not check their inclusion.",
		})
	}
	if err := s.appendQueuedEvent(ctx, tenantID, req.RequestedBy, payloads); err != nil {
		return api.CTLogSubmissionResponse{}, err
	}
	if err := s.enqueue(ctx, tenantID, payloads); err != nil {
		return api.CTLogSubmissionResponse{}, err
	}
	return res, nil
}

func (s *servedCTSubmissionService) enqueue(ctx context.Context, tenantID string, payloads []ctSubmissionPayload) error {
	return s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		for _, payload := range payloads {
			encoded, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			key, err := ctSubmissionPayloadOutboxKey(payload)
			if err != nil {
				return err
			}
			if _, err := s.outbox.EnqueueIfAbsent(ctx, tx, orchestrator.Entry{
				TenantID: tenantID, Destination: ctSubmissionDestination, IdempotencyKey: key, Payload: encoded,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *servedCTSubmissionService) appendQueuedEvent(ctx context.Context, tenantID, requestedBy string, payloads []ctSubmissionPayload) error {
	data := struct {
		Capability    string                `json:"capability"`
		RequestedBy   string                `json:"requested_by,omitempty"`
		QueuedAt      time.Time             `json:"queued_at"`
		SubmissionIDs []string              `json:"submission_ids"`
		OutboxKeys    []string              `json:"outbox_keys"`
		Logs          []string              `json:"logs"`
		Fingerprints  []string              `json:"fingerprints"`
		Payloads      []ctSubmissionPayload `json:"payloads,omitempty"`
	}{
		Capability:  ctSubmissionCapability,
		RequestedBy: requestedBy,
		Payloads:    append([]ctSubmissionPayload(nil), payloads...),
	}
	if len(payloads) > 0 {
		data.QueuedAt = payloads[0].QueuedAt
	}
	seenLogs := map[string]bool{}
	seenFingerprints := map[string]bool{}
	for _, p := range payloads {
		data.SubmissionIDs = append(data.SubmissionIDs, p.SubmissionID)
		key, err := ctSubmissionPayloadOutboxKey(p)
		if err != nil {
			return err
		}
		data.OutboxKeys = append(data.OutboxKeys, key)
		if !seenLogs[p.LogURL] {
			data.Logs = append(data.Logs, p.LogURL)
			seenLogs[p.LogURL] = true
		}
		if !seenFingerprints[p.LeafSHA256Fingerprint] {
			data.Fingerprints = append(data.Fingerprints, p.LeafSHA256Fingerprint)
			seenFingerprints[p.LeafSHA256Fingerprint] = true
		}
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = s.log.Append(ctx, events.Event{Type: ctSubmissionEventQueued, TenantID: tenantID, Data: encoded})
	return err
}

func ctSubmissionPayloadOutboxKey(payload ctSubmissionPayload) (string, error) {
	if payload.SubmissionID == "" || payload.EntryType == "" || payload.IdempotencyKey == "" {
		return "", errors.New("server: CT submission payload requires submission_id, entry_type, and idempotency_key")
	}
	if payload.EntryType != ctSubmissionPrecertificate && payload.EntryType != ctSubmissionCertificate {
		return "", fmt.Errorf("server: CT submission entry_type %q is invalid", payload.EntryType)
	}
	return fmt.Sprintf("%s:%s:%s:%s", ctSubmissionDestination, payload.IdempotencyKey, payload.EntryType, payload.SubmissionID), nil
}

type ctSubmissionPayload struct {
	Capability             string    `json:"capability"`
	SubmissionID           string    `json:"submission_id"`
	LogURL                 string    `json:"log_url"`
	EntryType              string    `json:"entry_type"`
	LeafDER                []byte    `json:"leaf_der"`
	ChainDER               [][]byte  `json:"chain_der,omitempty"`
	LeafSHA256Fingerprint  string    `json:"leaf_sha256_fingerprint"`
	Subject                string    `json:"subject"`
	SerialNumber           string    `json:"serial_number"`
	RequestedBy            string    `json:"requested_by,omitempty"`
	IdempotencyKey         string    `json:"idempotency_key"`
	AllowPrivateEndpoint   bool      `json:"allow_private_endpoint,omitempty"`
	PrivateEgressCIDRs     []string  `json:"private_egress_cidrs,omitempty"`
	SubmissionProfile      string    `json:"submission_profile,omitempty"`
	OperatorCorrelationRef string    `json:"operator_correlation_ref,omitempty"`
	QueuedAt               time.Time `json:"queued_at"`
	// LogPublicKey is the log's DER public key when the request named one
	// (A213).
	LogPublicKey []byte `json:"log_public_key,omitempty"`
	// CertificateFingerprint is the certificate a precertificate's SCT is
	// for; the SCT is shown on that certificate.
	CertificateFingerprint string `json:"certificate_sha256_fingerprint,omitempty"`
}

func (d *issuanceDispatcher) handleCTSubmission(ctx context.Context, m orchestrator.Message) error {
	var p ctSubmissionPayload
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return fmt.Errorf("server: decode CT submission payload: %w", err)
	}
	if p.Capability != ctSubmissionCapability {
		return fmt.Errorf("server: CT submission payload capability %q is invalid", p.Capability)
	}
	if p.EntryType != ctSubmissionPrecertificate && p.EntryType != ctSubmissionCertificate {
		return fmt.Errorf("server: CT submission entry_type %q is invalid", p.EntryType)
	}
	if strings.TrimSpace(p.LogURL) == "" {
		return errors.New("server: CT submission log_url is required")
	}
	if len(p.LeafDER) == 0 {
		return errors.New("server: CT submission leaf_der is required")
	}
	client, err := cloudHTTPClient(p.LogURL, p.AllowPrivateEndpoint, p.PrivateEgressCIDRs)
	if err != nil {
		return fmt.Errorf("server: CT submission log rejected: %w", err)
	}
	endpoint, err := ctSubmissionEndpoint(p.LogURL, p.EntryType)
	if err != nil {
		return err
	}
	body, err := ctSubmissionRequestBody(p.LeafDER, p.ChainDER)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("server: build CT submission request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", m.IdempotencyKey)
	req.Header.Set("X-Trstctl-Idempotency-Key", m.IdempotencyKey)
	req.Header.Set("X-Trstctl-Capability", ctSubmissionCapability)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("server: submit CT %s to %s: %w", p.EntryType, p.LogURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxCTSubmissionResponse))
	if err != nil {
		return fmt.Errorf("server: read CT submission response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("server: CT submission to %s returned %d: %s", p.LogURL, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	timestamp, err := validateCTSCTResponse(respBody)
	if err != nil {
		return fmt.Errorf("server: CT submission response from %s is invalid: %w", p.LogURL, err)
	}
	if d.orch != nil {
		sct := ctSCTRecord(p, respBody, timestamp)
		raw, err := json.Marshal(sct)
		if err != nil {
			return err
		}
		eventID := uuid.NewSHA1(ctSubmissionNamespace, append([]byte(projections.EventCertificateSCTRecorded+"\x00"), raw...)).String()
		if err := d.orch.RecordCertificateSCTWithEventID(ctx, m.TenantID, eventID, sct); err != nil {
			return fmt.Errorf("server: record the SCT from %s: %w", p.LogURL, err)
		}
	}
	if d.log != nil {
		data, err := json.Marshal(struct {
			Capability            string    `json:"capability"`
			SubmissionID          string    `json:"submission_id"`
			LogURL                string    `json:"log_url"`
			EntryType             string    `json:"entry_type"`
			LeafSHA256Fingerprint string    `json:"leaf_sha256_fingerprint"`
			Subject               string    `json:"subject"`
			SerialNumber          string    `json:"serial_number"`
			DeliveredAt           time.Time `json:"delivered_at"`
		}{
			Capability: ctSubmissionCapability, SubmissionID: p.SubmissionID, LogURL: p.LogURL,
			EntryType: p.EntryType, LeafSHA256Fingerprint: p.LeafSHA256Fingerprint, Subject: p.Subject,
			SerialNumber: p.SerialNumber, DeliveredAt: time.Now().UTC(),
		})
		if err != nil {
			return err
		}
		if _, err := d.log.Append(ctx, events.Event{Type: ctSubmissionEventDelivered, TenantID: m.TenantID, Data: data}); err != nil {
			return err
		}
	}
	return nil
}

func ctSubmissionID(tenantID, logURL, entryType, fingerprint string) string {
	return uuid.NewSHA1(ctSubmissionNamespace, []byte(tenantID+"\x00"+logURL+"\x00"+entryType+"\x00"+fingerprint)).String()
}

func decodeCertificateBundle(values []string, field string) ([][]byte, error) {
	var out [][]byte
	for i, value := range values {
		der, _, err := decodeCertificatePEMOrBase64(value, fmt.Sprintf("%s[%d]", field, i))
		if err != nil {
			return nil, err
		}
		out = append(out, der)
	}
	return out, nil
}

func decodeCertificatePEMOrBase64(value, field string) ([]byte, certinfo.Info, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, certinfo.Info{}, fmt.Errorf("%s is required", field)
	}
	var der []byte
	if block, _ := pem.Decode([]byte(trimmed)); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, certinfo.Info{}, fmt.Errorf("%s PEM block is %q, not CERTIFICATE", field, block.Type)
		}
		der = append([]byte(nil), block.Bytes...)
	} else if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(decoded) > 0 {
		der = decoded
	} else {
		return nil, certinfo.Info{}, fmt.Errorf("%s must be a CERTIFICATE PEM block or base64 DER", field)
	}
	info, err := certinfo.Inspect(der)
	if err != nil {
		return nil, certinfo.Info{}, fmt.Errorf("%s parse certificate: %w", field, err)
	}
	return der, info, nil
}

func ctSubmissionEndpoint(rawLogURL, entryType string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(rawLogURL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("server: invalid Certificate Transparency log URL %q", rawLogURL)
	}
	path := "/ct/v1/add-chain"
	if entryType == ctSubmissionPrecertificate {
		path = "/ct/v1/add-pre-chain"
	}
	base.Path = strings.TrimRight(base.Path, "/") + path
	base.RawQuery = ""
	base.Fragment = ""
	return base.String(), nil
}

func ctSubmissionRequestBody(leaf []byte, chain [][]byte) ([]byte, error) {
	body := struct {
		Chain []string `json:"chain"`
	}{
		Chain: []string{base64.StdEncoding.EncodeToString(leaf)},
	}
	for _, cert := range chain {
		if len(cert) == 0 {
			return nil, errors.New("server: CT submission chain contains an empty certificate")
		}
		body.Chain = append(body.Chain, base64.StdEncoding.EncodeToString(cert))
	}
	return json.Marshal(body)
}

func validateCTSCTResponse(body []byte) (uint64, error) {
	var out struct {
		SCTVersion int    `json:"sct_version"`
		ID         string `json:"id"`
		Timestamp  int64  `json:"timestamp"`
		Signature  string `json:"signature"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return 0, err
	}
	if out.ID == "" || out.Timestamp <= 0 || out.Signature == "" {
		return 0, errors.New("missing SCT id, timestamp, or signature")
	}
	return uint64(out.Timestamp), nil // #nosec G115 -- positive checked above (CWE-190)
}

// ctSCTRecord is what trstctl keeps of the SCT a log returned (A213): checked
// against the log key the request named, malformed or invalid with the
// reason, or unverified when no key was named.
func ctSCTRecord(p ctSubmissionPayload, body []byte, timestamp uint64) projections.CertificateSCTRecorded {
	fingerprint := p.CertificateFingerprint
	if fingerprint == "" {
		fingerprint = p.LeafSHA256Fingerprint
	}
	rec := projections.CertificateSCTRecorded{
		SubmissionID: p.SubmissionID, LeafFingerprint: fingerprint, LogURL: p.LogURL, EntryType: p.EntryType,
		SCTTimestampMillis: timestamp,
	}
	sct, err := ctlog.ParseSCT(body)
	if err != nil {
		rec.SCTStatus, rec.SCTReason = store.SCTInvalid, "the log returned a malformed SCT: "+err.Error()
		return rec
	}
	rec.LogID = hex.EncodeToString(sct.LogID)
	if len(p.LogPublicKey) == 0 {
		rec.SCTStatus, rec.SCTReason = store.SCTUnverified, "no public key was named for this log"
		return rec
	}
	chain := append([][]byte{p.LeafDER}, p.ChainDER...)
	leafHash, err := ctlog.VerifySCT(sct, p.LogPublicKey, chain, p.EntryType == ctSubmissionPrecertificate)
	if errors.Is(err, ctlog.ErrNotVerifiable) {
		rec.SCTStatus, rec.SCTReason = store.SCTUnverified, err.Error()
		return rec
	}
	if err != nil {
		rec.SCTStatus, rec.SCTReason = store.SCTInvalid, err.Error()
		return rec
	}
	rec.SCTStatus, rec.LeafHash, rec.LogPublicKey = store.SCTVerified, hex.EncodeToString(leafHash), p.LogPublicKey
	rec.AllowPrivateEndpoint = p.AllowPrivateEndpoint
	rec.PrivateEgressCIDRs = append([]string(nil), p.PrivateEgressCIDRs...)
	return rec
}

// ctLogPublicKeys decodes the log keys a request named (A213): each belongs to
// one of the request's logs and is an ECDSA or RSA public key.
func ctLogPublicKeys(raw map[string]string, logs []string) (map[string][]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	named := make(map[string]bool, len(logs))
	for _, logURL := range logs {
		named[logURL] = true
	}
	out := make(map[string][]byte, len(raw))
	for rawURL, value := range raw {
		logURL := strings.TrimSpace(rawURL)
		if !named[logURL] {
			return nil, fmt.Errorf("log_public_keys names certificate transparency log %q, which is not in logs", logURL)
		}
		if out[logURL] != nil {
			return nil, fmt.Errorf("log_public_keys names certificate transparency log %q twice", logURL)
		}
		der, err := decodeCTLogKey(value)
		if err != nil {
			return nil, fmt.Errorf("certificate transparency log %q public key is invalid: %w", logURL, err)
		}
		out[logURL] = der
	}
	return out, nil
}

func decodeCTLogKey(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	var der []byte
	if block, _ := pem.Decode([]byte(trimmed)); block != nil {
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("PEM block is %q, not PUBLIC KEY", block.Type)
		}
		der = block.Bytes
	} else if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(decoded) > 0 {
		der = decoded
	} else {
		return nil, errors.New("want base64 DER or a PUBLIC KEY PEM block")
	}
	if err := ctlog.ValidateLogKey(der); err != nil {
		return nil, err
	}
	return der, nil
}
