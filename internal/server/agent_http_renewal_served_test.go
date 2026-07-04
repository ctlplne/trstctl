package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// TestServedHTTPEnrollmentRenewalOverRealMTLS proves F54's embedded HTTP renewal is
// not merely mounted on the plain control-plane mux. The served binary exposes a
// narrow agent-CA mTLS listener for POST /enroll/renewal: a current agent cert
// succeeds, while missing or untrusted client certificates fail at the live TLS
// boundary before enrollment code can mint anything.
func TestServedHTTPEnrollmentRenewalOverRealMTLS(t *testing.T) {
	h := newServedHarness(t, config.Protocols{}, withAgentChannel)
	if !h.srv.AgentHTTPRenewalServed() {
		t.Fatal("agent HTTP renewal listener is not served")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.srv.serveAgentHTTPRenewal(ctx, ln) }()
	t.Cleanup(func() { cancel(); <-done })
	baseURL := "https://" + ln.Addr().String()

	current := bootstrapAgentIdentityForHTTPRenewal(t, h, "edge-http-renewal")
	renewalCSR := newAgentCSR(t, "edge-http-renewal")
	body, _ := json.Marshal(map[string]string{"csr": base64.StdEncoding.EncodeToString(renewalCSR)})

	validClient := agentHTTPRenewalClient(t, h, current)
	status, data, err := postHTTPRenewal(validClient, baseURL, body)
	if err != nil {
		t.Fatalf("valid client POST /enroll/renewal over mTLS: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("valid client POST /enroll/renewal = %d body %s, want 200", status, data)
	}
	var out struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode renewal response: %v", err)
	}
	if out.Certificate == "" {
		t.Fatal("renewal response did not include a certificate")
	}
	if _, err := mtls.FirstCertDER([]byte(out.Certificate)); err != nil {
		t.Fatalf("renewed certificate chain is not parseable: %v", err)
	}

	noCertClient := agentHTTPRenewalClient(t, h, nil)
	if status, data, err := postHTTPRenewal(noCertClient, baseURL, body); err == nil {
		t.Fatalf("missing client certificate reached HTTP handler: status=%d body=%s", status, data)
	}

	rogueCA, err := mtls.NewCA("rogue-agent-ca")
	if err != nil {
		t.Fatal(err)
	}
	rogueCert, err := rogueCA.IssueClientCertificate("edge-http-renewal", mtls.ClientCertTTL)
	if err != nil {
		t.Fatal(err)
	}
	rogueClient := agentHTTPRenewalClient(t, h, mtls.StaticSource(rogueCert))
	if status, data, err := postHTTPRenewal(rogueClient, baseURL, body); err == nil {
		t.Fatalf("untrusted client certificate reached HTTP handler: status=%d body=%s", status, data)
	}
}

func bootstrapAgentIdentityForHTTPRenewal(t *testing.T, h *servedHarness, cn string) *mtls.AgentIdentity {
	t.Helper()
	id, err := mtls.GenerateAgentKey(cn)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := id.CSR()
	if err != nil {
		t.Fatal(err)
	}
	token, err := h.srv.agentEnroll.IssueBootstrapToken(context.Background(), h.tenant, "")
	if err != nil {
		t.Fatalf("issue bootstrap token: %v", err)
	}
	chain, err := h.srv.agentEnroll.EnrollBootstrap(context.Background(), token, csr)
	if err != nil {
		t.Fatalf("bootstrap agent identity: %v", err)
	}
	if err := id.UseCertificate(chain); err != nil {
		t.Fatalf("adopt agent certificate: %v", err)
	}
	return id
}

func agentHTTPRenewalClient(t *testing.T, h *servedHarness, src mtls.ClientCertSource) *http.Client {
	t.Helper()
	tr, err := mtls.AgentHTTPTransport(src, h.srv.AgentCACertPEM(), "localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

func postHTTPRenewal(client *http.Client, baseURL string, body []byte) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, baseURL+"/enroll/renewal", bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data, nil
}
