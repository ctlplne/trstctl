// SPDX-License-Identifier: BUSL-1.1

// CR-068 integration: the agent cache must refuse a forged good status signed
// by the checked leaf. The DER fixture contains only public certificates and
// signed responses; its signing keys are never retained.
package crypto_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/revcache"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/revcacheposture"
)

func serveCR068ForgedOCSP(t *testing.T, caDER, responseDER []byte, serialHex string) (int, revcacheposture.Entry) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		serial, err := crypto.ParseOCSPRequestSerial(body)
		if err != nil || serial != serialHex {
			http.Error(w, "unexpected OCSP request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(responseDER)
	}))
	t.Cleanup(upstream.Close)
	manager, err := revcache.NewManager(revcache.ManagerConfig{Segment: "plant-8", Issuers: []revcache.IssuerConfig{{
		ID: "issuing-ca", IssuerDER: caDER,
		OCSP: &revcache.OCSPConfig{UpstreamURL: upstream.URL, LocalPath: "/ocsp/issuing-ca"},
	}}}, revcache.ManagerOptions{Client: upstream.Client(), Now: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	local := httptest.NewServer(manager)
	t.Cleanup(local.Close)
	request, err := crypto.BuildOCSPRequestForSerial(caDER, serialHex)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := local.Client().Post(local.URL+"/ocsp/issuing-ca", "application/ocsp-request", bytes.NewReader(request))
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	statuses := manager.Statuses()
	if len(statuses) != 1 {
		t.Fatalf("agent cache posture rows = %d, want one", len(statuses))
	}
	return resp.StatusCode, statuses[0]
}

func TestCR068AgentOCSPCacheRejectsLeafSignedGoodStatus(t *testing.T) {
	readFixture := func(data []byte, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	caDER := readFixture(os.ReadFile("testdata/cr068_issuer.der"))
	serialHex := strings.TrimSpace(string(readFixture(os.ReadFile("testdata/cr068_serial.txt"))))
	if serialHex == "" {
		t.Fatal("empty fixture serial")
	}
	t.Run("control: responder NOT issued by the CA is refused", func(t *testing.T) {
		code, row := serveCR068ForgedOCSP(t, caDER, readFixture(os.ReadFile("testdata/cr068_unrelated_signed_good.der")), serialHex)
		if code != http.StatusServiceUnavailable || row.SignatureVerified || row.DetailCode != "invalid_signature" {
			t.Fatalf("unrelated responder control = HTTP %d, posture %+v; want invalid signature refusal", code, row)
		}
	})
	t.Run("victim leaf's own key signs good for its own serial", func(t *testing.T) {
		code, row := serveCR068ForgedOCSP(t, caDER, readFixture(os.ReadFile("testdata/cr068_leaf_signed_good.der")), serialHex)
		if code != http.StatusServiceUnavailable || row.SignatureVerified || row.DetailCode != "invalid_signature" {
			t.Fatalf("leaf-signed good status = HTTP %d, posture %+v; want invalid signature refusal", code, row)
		}
	})
}
