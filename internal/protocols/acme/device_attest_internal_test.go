// SPDX-License-Identifier: MPL-2.0

package acme

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	trstcrypto "trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
)

type staticDeviceAttestationPolicy struct {
	tenant     string
	identifier string
	policy     DeviceAttestationPolicy
}

type deviceAttestEventLog struct {
	events []events.Event
	replay []events.Event
}

func (l *deviceAttestEventLog) Append(_ context.Context, event events.Event) (events.Event, error) {
	if event.SchemaVersion == 0 {
		event.SchemaVersion = events.DefaultSchemaVersion
	}
	l.events = append(l.events, event)
	return event, nil
}

func (l *deviceAttestEventLog) Replay(_ context.Context, _ uint64, apply func(events.Event) error) error {
	for _, event := range l.replay {
		if err := apply(event); err != nil {
			return err
		}
	}
	return nil
}

func (p staticDeviceAttestationPolicy) DeviceAttestationPolicy(_ context.Context, tenantID, identifier string) (DeviceAttestationPolicy, bool, error) {
	if tenantID != p.tenant || identifier != p.identifier {
		return DeviceAttestationPolicy{}, false, nil
	}
	return p.policy, true, nil
}

func TestDeviceAttestTPMIsDefaultOffAndProfileOptInDoesNotReplaceDV(t *testing.T) {
	const (
		tenant     = "tenant-device-attest"
		identifier = "host-01.example.test"
	)
	now := time.Date(2026, time.July, 28, 12, 0, 0, 0, time.UTC)
	identity, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}

	newOrder := func(t *testing.T, srv *Server) []string {
		t.Helper()
		srv.stateTenantID = tenant
		acct := &account{url: "http://ca.test/acme/acct/1", status: statusValid}
		msg := &jose.ACMEMessage{Payload: []byte(`{"identifiers":[{"type":"dns","value":"` + identifier + `"}]}`)}
		rec := httptest.NewRecorder()
		srv.newOrder(rec, httptest.NewRequest(http.MethodPost, "http://ca.test/acme/new-order", nil), msg, acct)
		if rec.Code != http.StatusCreated {
			t.Fatalf("new order status = %d: %s", rec.Code, rec.Body.String())
		}
		var types []string
		for _, az := range srv.authzs {
			for _, ch := range az.challenges {
				types = append(types, ch.typ)
			}
		}
		return types
	}

	withoutPolicy := newOrder(t, New(nil, AcceptAll{}))
	if len(withoutPolicy) != 3 || containsString(withoutPolicy, ChallengeDeviceAttest01) {
		t.Fatalf("default challenge types = %v, want exactly the three existing DV methods", withoutPolicy)
	}

	withPolicy := New(nil, AcceptAll{}).WithDeviceAttestationPolicy(staticDeviceAttestationPolicy{
		tenant: tenant, identifier: identifier,
		policy: DeviceAttestationPolicy{
			TrustedRootsPEM:   [][]byte{identity.RootPEM()},
			AllowedAlgorithms: []int64{-7},
			MaxAge:            5 * time.Minute,
		},
	})
	optedIn := newOrder(t, withPolicy)
	for _, want := range []string{ChallengeHTTP01, ChallengeDNS01, ChallengeTLSALPN01, ChallengeDeviceAttest01} {
		if !containsString(optedIn, want) {
			t.Fatalf("opted-in challenge types = %v, missing %q", optedIn, want)
		}
	}
}

func TestDeviceAttestTPMBindsOrderNonceCSRAndSurvivesStateReplay(t *testing.T) {
	now := time.Date(2026, time.July, 28, 12, 0, 0, 0, time.UTC)
	identity, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	srv, acct, order, az, ch := newDeviceAttestServer(t, identity.RootPEM(), now)
	msg := deviceAttestMessage(t, srv, acct, order, az, ch, identity, identity.CSRDER(), now, "nonce-1")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://ca.test/acme/chal/"+ch.id, nil)
	req.SetPathValue("id", ch.id)
	srv.acceptChallenge(rec, req, msg, acct)
	if rec.Code != http.StatusOK {
		t.Fatalf("valid TPM device attestation status = %d: %s", rec.Code, rec.Body.String())
	}
	if order.status != statusReady || ch.status != statusValid {
		t.Fatalf("validated state order=%q challenge=%q, want ready/valid", order.status, ch.status)
	}
	csrDigest, err := trstcrypto.CSRPublicKeySHA256(identity.CSRDER())
	if err != nil {
		t.Fatal(err)
	}
	if order.attestedKeySHA256 != base64.RawURLEncoding.EncodeToString(csrDigest) {
		t.Fatalf("event-sourced order key digest = %q, want %q", order.attestedKeySHA256, base64.RawURLEncoding.EncodeToString(csrDigest))
	}

	events := append([]events.Event(nil), srv.stateLog.(*deviceAttestEventLog).events...)
	replayed := New(nil, AcceptAll{}).WithDeviceAttestationPolicy(srv.deviceAttestationPolicy)
	if _, err := replayed.WithStateLog(context.Background(), srv.stateTenantID, &deviceAttestEventLog{replay: events}); err != nil {
		t.Fatalf("replay ACME device attestation state: %v", err)
	}
	replayedOrder := replayed.orders[order.id]
	if replayedOrder == nil || replayedOrder.attestedKeySHA256 != order.attestedKeySHA256 {
		t.Fatalf("replayed attested key digest = %+v, want %q", replayedOrder, order.attestedKeySHA256)
	}

	replayRec := httptest.NewRecorder()
	replayReq := httptest.NewRequest(http.MethodPost, "http://ca.test/acme/chal/"+ch.id, nil)
	replayReq.SetPathValue("id", ch.id)
	replayed.acceptChallenge(replayRec, replayReq, msg, acct)
	if replayRec.Code == http.StatusOK {
		t.Fatal("device-attest-01 replay unexpectedly succeeded")
	}
}

func TestDeviceAttestTPMRejectsKeyRootFreshnessOrderAndTenantMismatch(t *testing.T) {
	now := time.Date(2026, time.July, 28, 12, 0, 0, 0, time.UTC)
	identity, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		root         []byte
		csr          []byte
		issuedAt     time.Time
		bindOrder    string
		policyTenant string
	}{
		{name: "mismatched key", root: identity.RootPEM(), csr: other.CSRDER(), issuedAt: now},
		{name: "untrusted root", root: other.RootPEM(), csr: identity.CSRDER(), issuedAt: now},
		{name: "expired", root: identity.RootPEM(), csr: identity.CSRDER(), issuedAt: now.Add(-6 * time.Minute)},
		{name: "cross order", root: identity.RootPEM(), csr: identity.CSRDER(), issuedAt: now, bindOrder: "other-order"},
		{name: "cross tenant", root: identity.RootPEM(), csr: identity.CSRDER(), issuedAt: now, policyTenant: "other-tenant"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, acct, order, az, ch := newDeviceAttestServer(t, tc.root, now)
			if tc.policyTenant != "" {
				p := srv.deviceAttestationPolicy.(staticDeviceAttestationPolicy)
				p.tenant = tc.policyTenant
				srv.deviceAttestationPolicy = p
			}
			boundOrder := order
			if tc.bindOrder != "" {
				copyOrder := *order
				copyOrder.id = tc.bindOrder
				boundOrder = &copyOrder
			}
			msg := deviceAttestMessage(t, srv, acct, boundOrder, az, ch, identity, tc.csr, tc.issuedAt, "nonce-1")
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "http://ca.test/acme/chal/"+ch.id, nil)
			req.SetPathValue("id", ch.id)
			srv.acceptChallenge(rec, req, msg, acct)
			if rec.Code == http.StatusOK {
				t.Fatalf("%s unexpectedly accepted", tc.name)
			}
			if order.status != statusPending || ch.status != statusPending {
				t.Fatalf("failed proof mutated order=%q challenge=%q", order.status, ch.status)
			}
		})
	}
}

func TestDeviceAttestTPMFinalizeRejectsDifferentCSR(t *testing.T) {
	now := time.Date(2026, time.July, 28, 12, 0, 0, 0, time.UTC)
	identity, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	srv, acct, order, az, ch := newDeviceAttestServer(t, identity.RootPEM(), now)
	msg := deviceAttestMessage(t, srv, acct, order, az, ch, identity, identity.CSRDER(), now, "nonce-1")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://ca.test/acme/chal/"+ch.id, nil)
	req.SetPathValue("id", ch.id)
	srv.acceptChallenge(rec, req, msg, acct)
	if rec.Code != http.StatusOK {
		t.Fatalf("accept valid attestation: %d %s", rec.Code, rec.Body.String())
	}

	finalizePayload, err := json.Marshal(map[string]string{"csr": base64.RawURLEncoding.EncodeToString(other.CSRDER())})
	if err != nil {
		t.Fatal(err)
	}
	finalizeRec := httptest.NewRecorder()
	finalizeReq := httptest.NewRequest(http.MethodPost, "http://ca.test/acme/order/"+order.id+"/finalize", nil)
	finalizeReq.SetPathValue("id", order.id)
	srv.finalize(finalizeRec, finalizeReq, &jose.ACMEMessage{Payload: finalizePayload}, acct)
	if finalizeRec.Code != http.StatusBadRequest || !strings.Contains(finalizeRec.Body.String(), "attested key") {
		t.Fatalf("mismatched finalize status = %d body=%s, want badCSR attested-key rejection", finalizeRec.Code, finalizeRec.Body.String())
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func newDeviceAttestServer(t *testing.T, rootPEM []byte, now time.Time) (*Server, *account, *order, *authorization, *challenge) {
	t.Helper()
	const (
		tenant     = "tenant-device-attest"
		identifier = "host-01.example.test"
	)
	log := &deviceAttestEventLog{}
	srv := New(nil, AcceptAll{}).WithDeviceAttestationPolicy(staticDeviceAttestationPolicy{
		tenant: tenant, identifier: identifier,
		policy: DeviceAttestationPolicy{
			TrustedRootsPEM:   [][]byte{rootPEM},
			AllowedAlgorithms: []int64{-7},
			MaxAge:            5 * time.Minute,
		},
	})
	srv.deviceAttestNow = func() time.Time { return now }
	srv.stateTenantID = tenant
	srv.stateLog = log
	acct := &account{url: "http://ca.test/acme/acct/1", status: statusValid}
	order := &order{id: "order-1", accountURL: acct.url, domains: []string{identifier}, status: statusPending, createdAt: now}
	az := &authorization{id: "authz-1", orderID: order.id, domain: identifier, status: statusPending, createdAt: now}
	ch := &challenge{id: "challenge-1", typ: ChallengeDeviceAttest01, token: "token-1", status: statusPending, authzID: az.id}
	order.authzIDs = []string{az.id}
	az.challenges = []*challenge{ch}
	srv.orders[order.id] = order
	srv.authzs[az.id] = az
	srv.challenges[ch.id] = ch
	initialState, err := json.Marshal(orderCreatedEventFrom(order, []*authorization{az}, 1))
	if err != nil {
		t.Fatalf("encode initial device-attest order event: %v", err)
	}
	log.events = append(log.events, events.Event{
		Type:          acmeEventOrderCreated,
		TenantID:      tenant,
		SchemaVersion: events.DefaultSchemaVersion,
		Data:          initialState,
	})
	return srv, acct, order, az, ch
}

func deviceAttestMessage(
	t *testing.T,
	srv *Server,
	acct *account,
	order *order,
	az *authorization,
	ch *challenge,
	identity *deviceattesttest.TPMIdentity,
	csrDER []byte,
	issuedAt time.Time,
	nonce string,
) *jose.ACMEMessage {
	t.Helper()
	csrDigest, err := trstcrypto.CSRPublicKeySHA256(csrDER)
	if err != nil {
		t.Fatalf("digest CSR: %v", err)
	}
	challenge, err := deviceAttestationBinding(DeviceAttestationBinding{
		TenantID:     srv.stateTenantID,
		AccountURL:   acct.url,
		OrderID:      order.id,
		ChallengeID:  ch.id,
		Token:        ch.token,
		Nonce:        nonce,
		Identifier:   az.domain,
		CSRKeySHA256: csrDigest,
		IssuedAt:     issuedAt,
	})
	if err != nil {
		t.Fatalf("derive attestation binding: %v", err)
	}
	credentialJSON, err := identity.CredentialJSON(challenge)
	if err != nil {
		t.Fatalf("build credential JSON: %v", err)
	}
	payload, err := json.Marshal(DeviceAttestationResponse{
		DeviceIdentifier: az.domain,
		IssuedAt:         issuedAt,
		CSR:              base64.RawURLEncoding.EncodeToString(csrDER),
		Attestation:      credentialJSON,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &jose.ACMEMessage{
		Protected: jose.ACMEProtected{Nonce: nonce},
		Payload:   payload,
	}
}
