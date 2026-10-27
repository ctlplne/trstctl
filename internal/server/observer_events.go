// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/notify"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// observerEventSignatureHeader carries hex(HMAC-SHA256(credential, body)), the
// same scheme as signed webhook notifications.
const observerEventSignatureHeader = "X-Trstctl-Signature"

// observerEventEnvelope is an observer.event outbox row: which observer, and
// the exact event bytes to post.
type observerEventEnvelope struct {
	ObserverID string          `json:"observer_id"`
	Event      json.RawMessage `json:"event"`
}

// observerEventDelivery posts queued rotation and rollback events to external
// observers (A180). The event bytes were fixed when the event was queued; the
// credential is redeemed per attempt and wiped after it.
type observerEventDelivery struct {
	store       *store.Store
	credentials func(ctx context.Context, tenantID, ref string) (*secret.Buffer, error)
	client      notify.HTTPDoer
	// skipEndpointValidation is set only when a test injects a client that
	// reaches a loopback stand-in observer.
	skipEndpointValidation bool
}

func newObserverEventDelivery(st *store.Store, credentials func(ctx context.Context, tenantID, ref string) (*secret.Buffer, error)) *observerEventDelivery {
	return &observerEventDelivery{store: st, credentials: credentials, client: netsec.SafeClient(10 * time.Second)}
}

// Deliver posts one event. A 2xx response is delivered; a refusal the
// observer will repeat (a 4xx other than 408 and 429), a removed or disabled
// observer, or an unreadable row is terminal; anything else is retried.
func (d *observerEventDelivery) Deliver(ctx context.Context, m orchestrator.Message) error {
	var envelope observerEventEnvelope
	if err := json.Unmarshal(m.Payload, &envelope); err != nil || envelope.ObserverID == "" || len(envelope.Event) == 0 {
		return orchestrator.DefiniteNoEffect(errors.New("server: observer event row is unreadable"))
	}
	observer, err := d.store.GetExternalObserver(ctx, m.TenantID, envelope.ObserverID)
	if store.IsNotFound(err) {
		return orchestrator.DefiniteNoEffect(errors.New("server: the observer was removed before its event was delivered"))
	}
	if err != nil {
		return err
	}
	if !observer.Enabled || observer.EventsURL == "" {
		return orchestrator.DefiniteNoEffect(errors.New("server: the observer no longer receives events"))
	}
	if !d.skipEndpointValidation {
		if err := netsec.ValidatePublicHTTPSURL(observer.EventsURL); err != nil {
			return orchestrator.DefiniteNoEffect(fmt.Errorf("server: observer events URL: %w", err))
		}
	}
	body := []byte(envelope.Event)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, observer.EventsURL, bytes.NewReader(body))
	if err != nil {
		return orchestrator.DefiniteNoEffect(errors.New("server: observer events URL is not a valid request target"))
	}
	req.Header.Set("Content-Type", "application/json")
	if observer.CredentialRef != "" {
		if d.credentials == nil {
			return errors.New("server: observer credential references need the tenant secret store")
		}
		credential, err := d.credentials(ctx, m.TenantID, observer.CredentialRef)
		if err != nil {
			return errors.New("server: the observer's credential could not be resolved from the tenant secret store")
		}
		sig := hex.EncodeToString(crypto.HMACSHA256(credential.Bytes(), body))
		credential.Destroy()
		req.Header.Set(observerEventSignatureHeader, "sha256="+sig)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		if errors.Is(err, netsec.ErrSSRFBlocked) {
			return orchestrator.DefiniteNoEffect(fmt.Errorf("server: post observer event: %w", netsec.ErrSSRFBlocked))
		}
		// Transport errors can carry the URL; report only the class.
		return errors.New("server: post observer event: transport error")
	}
	defer func() { _ = resp.Body.Close() }()
	_ = secret.DrainBounded(resp.Body, 1<<16)
	return classifyObserverResponse(resp.StatusCode)
}

// deliverObserverEvent routes an observer.event row to the configured delivery.
func (d *issuanceDispatcher) deliverObserverEvent(ctx context.Context, m orchestrator.Message) error {
	if d.observerEvents == nil {
		return orchestrator.DefiniteNoEffect(errors.New("server: observer event delivery is not configured"))
	}
	return d.observerEvents.Deliver(ctx, m)
}

// classifyObserverResponse maps the observer's status to the outbox outcome.
func classifyObserverResponse(status int) error {
	switch {
	case status/100 == 2:
		return nil
	case status/100 == 4 && status != http.StatusRequestTimeout && status != http.StatusTooManyRequests:
		return orchestrator.DefiniteNoEffect(fmt.Errorf("server: the observer refused the event with status %d", status))
	default:
		return fmt.Errorf("server: the observer answered status %d", status)
	}
}
