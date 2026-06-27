package acme

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/profile"
)

const (
	acmeEventPrefix             = "acme."
	acmeEventAccountUpserted    = "acme.account.upserted"
	acmeEventOrderCreated       = "acme.order.created"
	acmeEventChallengeValidated = "acme.challenge.validated"
	acmeEventCertificateIssued  = "acme.certificate.issued"
	acmeEventCertificateRevoked = "acme.certificate.revoked"
	acmeEventEarlyRenewalMarked = "acme.ari.early_renewal_marked"
)

type eventLog interface {
	Append(context.Context, events.Event) (events.Event, error)
	Replay(context.Context, uint64, func(events.Event) error) error
}

type acmeAccountEvent struct {
	Seq     int             `json:"seq,omitempty"`
	ID      string          `json:"id"`
	URL     string          `json:"url"`
	JWK     json.RawMessage `json:"jwk"`
	Contact []string        `json:"contact,omitempty"`
	Status  string          `json:"status"`
}

type acmeOrderState struct {
	ID         string    `json:"id"`
	AccountURL string    `json:"account_url"`
	Domains    []string  `json:"domains"`
	AuthzIDs   []string  `json:"authz_ids"`
	Status     string    `json:"status"`
	AuthMode   string    `json:"auth_mode,omitempty"`
	CertID     string    `json:"cert_id,omitempty"`
	Replaces   string    `json:"replaces,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

type acmeAuthorizationState struct {
	ID         string               `json:"id"`
	OrderID    string               `json:"order_id"`
	Domain     string               `json:"domain"`
	Status     string               `json:"status"`
	CreatedAt  time.Time            `json:"created_at"`
	Challenges []acmeChallengeState `json:"challenges"`
}

type acmeChallengeState struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Token   string `json:"token"`
	Status  string `json:"status"`
	AuthzID string `json:"authz_id"`
}

type acmeOrderCreatedEvent struct {
	Seq            int                      `json:"seq,omitempty"`
	Order          acmeOrderState           `json:"order"`
	Authorizations []acmeAuthorizationState `json:"authorizations"`
}

type acmeChallengeValidatedEvent struct {
	ChallengeID     string `json:"challenge_id"`
	AuthzID         string `json:"authz_id"`
	OrderID         string `json:"order_id"`
	ChallengeStatus string `json:"challenge_status"`
	AuthzStatus     string `json:"authz_status"`
	OrderStatus     string `json:"order_status,omitempty"`
}

type acmeIssuedState struct {
	AccountURL string `json:"account_url"`
	KeyThumb   string `json:"key_thumb,omitempty"`
	Serial     string `json:"serial,omitempty"`
	CertID     string `json:"cert_id"`
}

type acmeCertificateIssuedEvent struct {
	Seq            int             `json:"seq,omitempty"`
	OrderID        string          `json:"order_id"`
	CertID         string          `json:"cert_id"`
	CertificatePEM []byte          `json:"certificate_pem"`
	ARICertID      string          `json:"ari_cert_id,omitempty"`
	NotBefore      time.Time       `json:"not_before,omitempty"`
	NotAfter       time.Time       `json:"not_after,omitempty"`
	Fingerprint    string          `json:"fingerprint,omitempty"`
	Issued         acmeIssuedState `json:"issued"`
}

type acmeCertificateRevokedEvent struct {
	Fingerprint string    `json:"fingerprint"`
	Serial      string    `json:"serial,omitempty"`
	Reason      int       `json:"reason"`
	At          time.Time `json:"at"`
}

type acmeEarlyRenewalEvent struct {
	CertID string `json:"cert_id"`
}

// WithStateLog attaches the tenant-scoped source-of-truth event log and rebuilds
// the ACME serving view before traffic is accepted. A replay error is a startup
// error because serving with an incomplete account/order/cert view would lose ACME
// lifecycle correctness after restart.
func (s *Server) WithStateLog(ctx context.Context, tenantID string, log eventLog) (*Server, error) {
	if tenantID == "" {
		return nil, errors.New("acme: state log tenant_id is required")
	}
	if log == nil {
		return nil, errors.New("acme: state log is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stateTenantID = tenantID
	s.stateLog = log
	if err := log.Replay(ctx, 1, func(ev events.Event) error {
		if ev.TenantID != tenantID || !strings.HasPrefix(ev.Type, acmeEventPrefix) {
			return nil
		}
		return s.applyStateEventLocked(ev)
	}); err != nil {
		s.stateTenantID = ""
		s.stateLog = nil
		return nil, fmt.Errorf("acme: replay state: %w", err)
	}
	return s, nil
}

func (s *Server) appendStateEventLocked(ctx context.Context, typ string, payload any) error {
	if s.stateLog == nil {
		return nil
	}
	if s.stateTenantID == "" {
		return errors.New("acme: state log configured without tenant_id")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("acme: encode %s event: %w", typ, err)
	}
	if _, err := s.stateLog.Append(ctx, events.Event{Type: typ, TenantID: s.stateTenantID, Data: data}); err != nil {
		return fmt.Errorf("acme: append %s event: %w", typ, err)
	}
	return nil
}

func (s *Server) applyStateEventLocked(ev events.Event) error {
	if ev.SchemaVersion != events.DefaultSchemaVersion {
		return fmt.Errorf("acme: unsupported %s schema version %d", ev.Type, ev.SchemaVersion)
	}
	switch ev.Type {
	case acmeEventAccountUpserted:
		var payload acmeAccountEvent
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			return fmt.Errorf("acme: decode account event: %w", err)
		}
		return s.applyAccountEventLocked(payload)
	case acmeEventOrderCreated:
		var payload acmeOrderCreatedEvent
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			return fmt.Errorf("acme: decode order event: %w", err)
		}
		return s.applyOrderCreatedEventLocked(payload)
	case acmeEventChallengeValidated:
		var payload acmeChallengeValidatedEvent
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			return fmt.Errorf("acme: decode challenge event: %w", err)
		}
		return s.applyChallengeValidatedEventLocked(payload)
	case acmeEventCertificateIssued:
		var payload acmeCertificateIssuedEvent
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			return fmt.Errorf("acme: decode certificate event: %w", err)
		}
		return s.applyCertificateIssuedEventLocked(payload)
	case acmeEventCertificateRevoked:
		var payload acmeCertificateRevokedEvent
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			return fmt.Errorf("acme: decode revocation event: %w", err)
		}
		return s.applyCertificateRevokedEventLocked(payload)
	case acmeEventEarlyRenewalMarked:
		var payload acmeEarlyRenewalEvent
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			return fmt.Errorf("acme: decode early-renewal event: %w", err)
		}
		return s.applyEarlyRenewalEventLocked(payload)
	default:
		return nil
	}
}

func (s *Server) applyAccountEventLocked(payload acmeAccountEvent) error {
	if payload.URL == "" || payload.ID == "" || len(payload.JWK) == 0 {
		return errors.New("acme: malformed account event")
	}
	key, err := jose.ACMEKeyFromJWK(payload.JWK)
	if err != nil {
		return fmt.Errorf("acme: account key replay: %w", err)
	}
	acct := s.accounts[payload.URL]
	if acct == nil {
		acct = &account{url: payload.URL}
	}
	oldID := acct.id
	acct.id = payload.ID
	acct.key = key
	acct.jwk = copyRawMessage(payload.JWK)
	acct.contact = append([]string(nil), payload.Contact...)
	acct.status = payload.Status
	if acct.status == "" {
		acct.status = statusValid
	}
	s.accounts[acct.url] = acct
	if oldID != "" && oldID != acct.id {
		delete(s.byKey, oldID)
	}
	s.byKey[acct.id] = acct
	s.rememberSeq(payload.Seq)
	return nil
}

func (s *Server) applyOrderCreatedEventLocked(payload acmeOrderCreatedEvent) error {
	if payload.Order.ID == "" || payload.Order.AccountURL == "" {
		return errors.New("acme: malformed order event")
	}
	o := &order{
		id:         payload.Order.ID,
		accountURL: payload.Order.AccountURL,
		domains:    append([]string(nil), payload.Order.Domains...),
		authzIDs:   append([]string(nil), payload.Order.AuthzIDs...),
		status:     payload.Order.Status,
		authMode:   profileACMEAuthMode(payload.Order.AuthMode),
		certID:     payload.Order.CertID,
		replaces:   payload.Order.Replaces,
		createdAt:  payload.Order.CreatedAt,
	}
	if o.status == "" {
		o.status = statusPending
	}
	s.orders[o.id] = o
	for _, azPayload := range payload.Authorizations {
		if azPayload.ID == "" || azPayload.OrderID == "" {
			return errors.New("acme: malformed authorization event")
		}
		az := &authorization{
			id:        azPayload.ID,
			orderID:   azPayload.OrderID,
			domain:    azPayload.Domain,
			status:    azPayload.Status,
			createdAt: azPayload.CreatedAt,
		}
		if az.status == "" {
			az.status = statusPending
		}
		for _, chPayload := range azPayload.Challenges {
			if chPayload.ID == "" || chPayload.AuthzID == "" {
				return errors.New("acme: malformed challenge event")
			}
			ch := &challenge{
				id:      chPayload.ID,
				typ:     chPayload.Type,
				token:   chPayload.Token,
				status:  chPayload.Status,
				authzID: chPayload.AuthzID,
			}
			if ch.status == "" {
				ch.status = statusPending
			}
			az.challenges = append(az.challenges, ch)
			s.challenges[ch.id] = ch
		}
		s.authzs[az.id] = az
	}
	s.rememberSeq(payload.Seq)
	return nil
}

func (s *Server) applyChallengeValidatedEventLocked(payload acmeChallengeValidatedEvent) error {
	ch := s.challenges[payload.ChallengeID]
	az := s.authzs[payload.AuthzID]
	if ch == nil || az == nil {
		return errors.New("acme: challenge validation event references missing state")
	}
	ch.status = payload.ChallengeStatus
	if ch.status == "" {
		ch.status = statusValid
	}
	az.status = payload.AuthzStatus
	if az.status == "" {
		az.status = statusValid
	}
	if payload.OrderID != "" && payload.OrderStatus != "" {
		if o := s.orders[payload.OrderID]; o != nil {
			o.status = payload.OrderStatus
		}
	}
	return nil
}

func (s *Server) applyCertificateIssuedEventLocked(payload acmeCertificateIssuedEvent) error {
	if payload.OrderID == "" || payload.CertID == "" {
		return errors.New("acme: malformed certificate-issued event")
	}
	o := s.orders[payload.OrderID]
	if o == nil {
		return errors.New("acme: certificate-issued event references missing order")
	}
	o.certID = payload.CertID
	o.status = statusValid
	s.certs[payload.CertID] = append([]byte(nil), payload.CertificatePEM...)
	if payload.ARICertID != "" {
		s.ariWindows[payload.ARICertID] = ariWindow{notBefore: payload.NotBefore, notAfter: payload.NotAfter}
	}
	if payload.Fingerprint != "" {
		s.issued[payload.Fingerprint] = &issuedCert{
			accountURL: payload.Issued.AccountURL,
			keyThumb:   payload.Issued.KeyThumb,
			serial:     payload.Issued.Serial,
			certID:     payload.Issued.CertID,
		}
	}
	s.rememberSeq(payload.Seq)
	return nil
}

func (s *Server) applyCertificateRevokedEventLocked(payload acmeCertificateRevokedEvent) error {
	if payload.Fingerprint == "" {
		return errors.New("acme: malformed certificate-revoked event")
	}
	s.revoked[payload.Fingerprint] = revocation{serial: payload.Serial, reason: payload.Reason, at: payload.At}
	return nil
}

func (s *Server) applyEarlyRenewalEventLocked(payload acmeEarlyRenewalEvent) error {
	if payload.CertID == "" {
		return errors.New("acme: malformed early-renewal event")
	}
	s.earlyRenew[payload.CertID] = true
	return nil
}

func accountEventFrom(acct *account, seq int) acmeAccountEvent {
	return acmeAccountEvent{
		Seq:     seq,
		ID:      acct.id,
		URL:     acct.url,
		JWK:     copyRawMessage(acct.jwk),
		Contact: append([]string(nil), acct.contact...),
		Status:  acct.status,
	}
}

func orderCreatedEventFrom(o *order, authzs []*authorization, seq int) acmeOrderCreatedEvent {
	payload := acmeOrderCreatedEvent{
		Seq: seq,
		Order: acmeOrderState{
			ID:         o.id,
			AccountURL: o.accountURL,
			Domains:    append([]string(nil), o.domains...),
			AuthzIDs:   append([]string(nil), o.authzIDs...),
			Status:     o.status,
			AuthMode:   string(o.authMode),
			CertID:     o.certID,
			Replaces:   o.replaces,
			CreatedAt:  o.createdAt,
		},
	}
	for _, az := range authzs {
		azPayload := acmeAuthorizationState{
			ID:        az.id,
			OrderID:   az.orderID,
			Domain:    az.domain,
			Status:    az.status,
			CreatedAt: az.createdAt,
		}
		for _, ch := range az.challenges {
			azPayload.Challenges = append(azPayload.Challenges, acmeChallengeState{
				ID:      ch.id,
				Type:    ch.typ,
				Token:   ch.token,
				Status:  ch.status,
				AuthzID: ch.authzID,
			})
		}
		payload.Authorizations = append(payload.Authorizations, azPayload)
	}
	return payload
}

func certificateIssuedEventFrom(orderID, certID, accountURL string, certificatePEM []byte, serial string, seq int) acmeCertificateIssuedEvent {
	payload := acmeCertificateIssuedEvent{
		Seq:            seq,
		OrderID:        orderID,
		CertID:         certID,
		CertificatePEM: append([]byte(nil), certificatePEM...),
		Issued:         acmeIssuedState{AccountURL: accountURL, Serial: serial, CertID: certID},
	}
	if block, _ := pem.Decode(certificatePEM); block != nil {
		if certid, err := certinfo.ARICertID(block.Bytes); err == nil {
			payload.ARICertID = certid
		}
		if fp := certFingerprint(block.Bytes); fp != "" {
			payload.Fingerprint = fp
		}
		if thumb, err := certinfo.PublicKeyJWKThumbprint(block.Bytes); err == nil {
			payload.Issued.KeyThumb = thumb
		}
		if info, err := certinfo.Inspect(block.Bytes); err == nil {
			payload.NotBefore = info.NotBefore
			payload.NotAfter = info.NotAfter
			if payload.Issued.Serial == "" {
				payload.Issued.Serial = info.SerialNumber
			}
		}
	}
	return payload
}

func challengeValidatedEventFrom(ch *challenge, az *authorization, o *order, orderStatus string) acmeChallengeValidatedEvent {
	payload := acmeChallengeValidatedEvent{
		ChallengeID:     ch.id,
		AuthzID:         az.id,
		OrderID:         az.orderID,
		ChallengeStatus: statusValid,
		AuthzStatus:     statusValid,
	}
	if o != nil {
		payload.OrderID = o.id
		payload.OrderStatus = orderStatus
	}
	return payload
}

func copyRawMessage(raw json.RawMessage) json.RawMessage {
	return append(json.RawMessage(nil), raw...)
}

func profileACMEAuthMode(raw string) profile.ACMEAuthMode {
	mode, err := profile.NormalizeACMEAuthMode(profile.ACMEAuthMode(raw))
	if err != nil {
		return profile.ACMEAuthModePublicTrust
	}
	return mode
}

func (s *Server) rememberSeq(seq int) {
	if seq > s.seq {
		s.seq = seq
	}
}
