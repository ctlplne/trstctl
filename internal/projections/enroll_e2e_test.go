package projections_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/server"
)

// TestAssembledServerEnrollsAgent is the R1.4 acceptance for the previously
// unmounted agent-enrollment handler: against the assembled control plane, an
// operator mints a one-time bootstrap token through the authenticated API, and an
// agent then presents that token plus a locally-generated CSR at the mounted
// POST /enroll/bootstrap route and receives a client certificate that chains to
// the enrollment CA. The token is one-time, so replaying it is rejected. Before
// R1.4 the wizard advertised /enroll/bootstrap but nothing served it.
func TestAssembledServerEnrollsAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("assembles the control plane with a real signer child; skipped in -short")
	}
	st := newStore(t)
	log := openLog(t)
	prov, stop := startSignerChild(t)
	defer stop()

	asm, err := server.Build(context.Background(), server.Deps{Store: st, Log: log, Signer: prov})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	ts := httptest.NewServer(asm.Handler())
	defer ts.Close()

	// Operator mints a one-time bootstrap token through the authenticated API.
	opToken := mintToken(t, st, "agents:write")
	code, body := req(t, ts, http.MethodPost, "/api/v1/agents/enrollment-tokens", opToken, "")
	if code != http.StatusCreated {
		t.Fatalf("mint enrollment token = %d: %s", code, body)
	}
	bootstrap, _ := decode(t, body)["token"].(string)
	if bootstrap == "" {
		t.Fatalf("no bootstrap token in response: %s", body)
	}

	// The agent generates its key locally and submits only a CSR (the private key
	// never reaches the control plane).
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "agent-01"}, key)
	if err != nil {
		t.Fatal(err)
	}
	enrollBody, err := json.Marshal(map[string]string{"token": bootstrap, "csr": base64.StdEncoding.EncodeToString(csrDER)})
	if err != nil {
		t.Fatal(err)
	}

	// Present token + CSR at the mounted enrollment route. The token authenticates
	// the request, so no bearer is sent.
	code, body = req(t, ts, http.MethodPost, "/enroll/bootstrap", "", string(enrollBody))
	if code != http.StatusOK {
		t.Fatalf("POST /enroll/bootstrap = %d: %s (the enrollment handler must be mounted)", code, body)
	}
	resp := decode(t, body)
	certPEM, _ := resp["certificate"].(string)
	caPEM, _ := resp["ca_bundle"].(string)
	leafBlk, _ := pem.Decode([]byte(certPEM))
	caBlk, _ := pem.Decode([]byte(caPEM))
	if leafBlk == nil || caBlk == nil {
		t.Fatalf("enroll response missing PEM certificate/ca_bundle: %s", body)
	}
	if err := crypto.VerifyLeafSignedByCA(leafBlk.Bytes, caBlk.Bytes); err != nil {
		t.Fatalf("enrolled client certificate does not chain to the enrollment CA: %v", err)
	}

	// The bootstrap token is one-time: presenting it again is rejected (401). The
	// /enroll route is not idempotency-guarded, so the second call truly executes.
	code, body = req(t, ts, http.MethodPost, "/enroll/bootstrap", "", string(enrollBody))
	if code != http.StatusUnauthorized {
		t.Fatalf("reused bootstrap token = %d, want 401 (one-time): %s", code, body)
	}
}
