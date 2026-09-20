// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// enrollOnlyEnroller is a minimal agent enroller so api.New mounts the enrollment
// routes without the full server assembly.
type enrollOnlyEnroller struct {
	renewalPeerChains [][][]byte
}

func (enrollOnlyEnroller) EnrollBootstrap(_ context.Context, _ []byte, _ []byte) ([]byte, error) {
	return []byte("-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----\n"), nil
}
func (e *enrollOnlyEnroller) EnrollRenewal(_ context.Context, peerCertsDER [][]byte, _ []byte) ([]byte, error) {
	if len(peerCertsDER) == 0 {
		return nil, context.Canceled
	}
	e.renewalPeerChains = append(e.renewalPeerChains, peerCertsDER)
	return []byte("-----BEGIN CERTIFICATE-----\nrenewed\n-----END CERTIFICATE-----\n"), nil
}
func (enrollOnlyEnroller) CABundlePEM() []byte {
	return []byte("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n")
}

// TestEnrollRoutesServed pins the exact /enroll/* split: bootstrap is on the
// primary control-plane mux, while renewal is exposed only through the narrow handler
// the server places behind the dedicated agent-CA mTLS listener. Renewal is not a
// public mint endpoint: it must reject a request without a verified current agent
// certificate, reject an expired presented certificate, and pass only the verified
// peer chain into the enrollment authority.
func TestEnrollRoutesServed(t *testing.T) {
	enroller := &enrollOnlyEnroller{}
	a := api.New(nil, nil, nil, api.WithAgentEnroller(enroller))
	renewalHandler := a.AgentRenewalHandler()

	bootstrapBody, _ := json.Marshal(map[string]string{
		"token": "tok",
		"csr":   base64.StdEncoding.EncodeToString([]byte("csr-der")),
	})
	renewalBody, _ := json.Marshal(map[string]string{
		"csr": base64.StdEncoding.EncodeToString([]byte("csr-der")),
	})

	post := func(handler http.Handler, path string, body []byte, tlsState bool) (int, string) {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		if tlsState {
			req.TLS = agentPeerTLSState(t, time.Hour).ConnectionState()
		}
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}

	// Bootstrap IS served: it must not 404 (the stub enroller returns a chain → 200).
	if code, _ := post(a, "/enroll/bootstrap", bootstrapBody, false); code == http.StatusNotFound {
		t.Errorf("POST /enroll/bootstrap should be served, got 404")
	}

	if code, _ := post(a, "/enroll/renewal", renewalBody, false); code != http.StatusNotFound {
		t.Fatalf("primary API mux POST /enroll/renewal = %d, want 404; renewal must stay on the dedicated mTLS listener", code)
	}

	if code, body := post(renewalHandler, "/enroll/renewal", renewalBody, false); code != http.StatusUnauthorized {
		t.Fatalf("POST /enroll/renewal without verified client cert = %d, want 401: %s", code, body)
	}
	if len(enroller.renewalPeerChains) != 0 {
		t.Fatal("unauthenticated renewal reached the enrollment authority")
	}

	if code, body := post(renewalHandler, "/enroll/renewal", renewalBody, true); code != http.StatusOK || !strings.Contains(body, "renewed") {
		t.Fatalf("POST /enroll/renewal with verified client cert = %d body %q, want 200 renewed certificate", code, body)
	}
	if len(enroller.renewalPeerChains) != 1 || len(enroller.renewalPeerChains[0]) == 0 {
		t.Fatalf("renewal peer chains = %#v, want one verified peer chain", enroller.renewalPeerChains)
	}

	expiredReq := httptest.NewRequest(http.MethodPost, "/enroll/renewal", bytes.NewReader(renewalBody))
	expiredReq.TLS = agentPeerTLSState(t, -time.Hour).ConnectionState()
	expiredReq.Header.Set("Content-Type", "application/json")
	expiredRec := httptest.NewRecorder()
	renewalHandler.ServeHTTP(expiredRec, expiredReq)
	if expiredRec.Code != http.StatusUnauthorized {
		t.Fatalf("POST /enroll/renewal with expired client cert = %d, want 401", expiredRec.Code)
	}

	// And there is no served reenroll alias either.
	if code, _ := post(renewalHandler, "/enroll/reenroll", renewalBody, false); code != http.StatusNotFound {
		t.Errorf("POST /enroll/reenroll should not be served, got %d", code)
	}
}

func agentPeerTLSState(t *testing.T, ttl time.Duration) *crypto.TLSConnectionState {
	t.Helper()
	ca, err := mtls.NewCA("test-agent-ca")
	if err != nil {
		t.Fatal(err)
	}
	id, err := mtls.GenerateAgentKey("edge-agent-1")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ca.SignClientCSRWithTenant(csr, "11111111-1111-1111-1111-111111111111", nil, ttl)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := mtls.FirstCertDER(chain)
	if err != nil {
		t.Fatal(err)
	}
	state, err := crypto.TLSStateWithPeerCertificates([][]byte{leaf})
	if err != nil {
		t.Fatal(err)
	}
	return state
}
