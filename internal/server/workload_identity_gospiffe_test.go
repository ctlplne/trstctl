// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

type stockIdentityCertificate struct {
	DER         []byte `json:"der"`
	CA          []byte `json:"ca"`
	TrustDomain string `json:"trust_domain"`
}

type stockIdentityCheck struct {
	Accepted bool   `json:"accepted"`
	ID       string `json:"id"`
	Error    string `json:"error"`
}

type stockIdentityResults struct {
	IDs          []stockIdentityCheck `json:"ids"`
	Certificates []stockIdentityCheck `json:"certificates"`
}

func runStockIdentityChecks(t *testing.T, ids []string, certificates []stockIdentityCertificate) stockIdentityResults {
	t.Helper()
	input, err := json.Marshal(struct {
		IDs          []string                   `json:"ids"`
		Certificates []stockIdentityCertificate `json:"certificates"`
	}{ids, certificates})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	// The existing nested fixture pins go-spiffe. No dependency enters the
	// control plane or sacred signer; no compatibility flags relax its parser.
	cmd := exec.CommandContext(ctx, "go", "run", "-mod=readonly", ".", "check-identities")
	cmd.Dir = filepath.Join("testdata", "gospiffe-client")
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("stock public-identity verification failed: %v\n%s", err, out)
	}
	var result stockIdentityResults
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.IDs) != len(ids) || len(result.Certificates) != len(certificates) {
		t.Fatal("stock verifier omitted results")
	}
	return result
}

func TestSPIFFEIdentityGrammarMatchesStockParser(t *testing.T) {
	ids := []string{"", "spiffe://", "spiffe://served.test", "spiffe://served.test/", "spiffe://served.test/a/../b", "spiffe://served.test/a//b", "spiffe://served.test/a%2Fb", "SPIFFE://served.test/a", "spiffe://SERVED.test/a", "spiffe://served.test:443/a"}
	for c := 0; c < 128; c++ {
		ids = append(ids, "spiffe://a"+string(rune(c))+"b.test/a", "spiffe://served.test/a"+string(rune(c))+"b")
	}
	for _, subject := range []string{"agent-7", "ns/qa/sa/web", "repo:org/project:ref:refs/heads/main", "a%2Fb", "trstctl-hex-613a62", "agent/ns/qa/sa/web", "é"} {
		for _, makeID := range []func(string, string) (string, error){testBrokerSPIFFEID, testAttestedSPIFFEID} {
			id, err := makeID("served.test", subject)
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
	}
	got := runStockIdentityChecks(t, ids, nil)
	for i, id := range ids {
		parsed, err := crypto.ParseSPIFFEID(id)
		if (err == nil) != got.IDs[i].Accepted {
			t.Errorf("grammar disagreement for %q: local=%v stock=%v", id, err, got.IDs[i])
		}
		if err == nil && parsed.String() != got.IDs[i].ID {
			t.Errorf("normalization disagreement for %q", id)
		}
	}
}

func TestServedWorkloadIdentitiesVerifyWithStockSPIFFE(t *testing.T) {
	h, owner, body := servedPublicBrokerRevocationFixture(t, func(d *Deps) {
		d.AttestedIssuance = AttestedIssuanceConfig{Enabled: true, TrustDomain: "served.test"}
	})
	githubKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer githubKey.Destroy()
	githubJWK, err := crypto.PublicJWK(githubKey.Public(), "identity-gh")
	if err != nil {
		t.Fatal(err)
	}
	status, _ := secretsReqKey(t, h, http.MethodPost, "/api/v1/workloads/attester-trust-sources", owner, "identity-gh-trust", map[string]any{
		"name": "identity-gh-trust", "method": "github_oidc", "issuer": "https://token.actions.githubusercontent.com", "audience": "trstctl",
		"jwks": crypto.JWKS{Keys: []crypto.JWK{githubJWK}},
	})
	if status != http.StatusCreated {
		t.Fatalf("register GitHub proof trust: HTTP %d", status)
	}
	const githubSubject = "repo:org/project:ref:refs/heads/main"
	proof, err := crypto.SignJWT(githubKey, "identity-gh", map[string]any{
		"iss": "https://token.actions.githubusercontent.com", "aud": "trstctl", "sub": githubSubject,
		"repository": "org/project", "repository_owner": "org", "exp": time.Now().Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	certificates := []stockIdentityCertificate{}
	wantIDs := []string{}
	for _, method := range []string{"k8s_sat", "github_oidc"} {
		request := make(map[string]any, len(body))
		for k, v := range body {
			request[k] = v
		}
		subject := "ns/qa/sa/clock-reader"
		path := subject
		if method == "github_oidc" {
			request["method"] = method
			request["payload_base64"] = base64.StdEncoding.EncodeToString([]byte(proof))
			subject = githubSubject
			path = "trstctl-hex-7265706f3a6f7267/trstctl-hex-70726f6a6563743a7265663a72656673/heads/main"
		}
		for _, surface := range []string{"broker", "attested"} {
			route, namespace := "/api/v1/broker/agent-identities", "/broker/agent/agent-7/"
			if surface == "attested" {
				route, namespace = "/api/v1/workloads/attested-issuance", "/attested/"
				delete(request, "agent_id")
				delete(request, "scopes")
			}
			status, raw := secretsReqKey(t, h, http.MethodPost, route, owner, "stock-identity-"+surface+"-"+method, request)
			var response struct {
				CertificatePEM string `json:"certificate_pem"`
				Subject        string `json:"subject"`
			}
			if status != http.StatusCreated || json.Unmarshal(raw, &response) != nil {
				t.Fatalf("%s %s issuance failed: HTTP %d", surface, method, status)
			}
			if response.Subject != subject {
				t.Fatalf("%s changed the original attested subject", surface)
			}
			block, rest := pem.Decode([]byte(response.CertificatePEM))
			if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
				t.Fatal("expected one public certificate")
			}
			certificates = append(certificates, stockIdentityCertificate{DER: block.Bytes, CA: h.srv.agentBroker.caCertDER, TrustDomain: "served.test"})
			wantIDs = append(wantIDs, "spiffe://served.test/_trstctl/v1/tenant/"+h.tenant+namespace+"method/"+method+"/subject/"+path)
		}
	}
	// Calibrate chain validation: a corrupted signed leaf and the right leaf
	// associated with the wrong trust domain must both fail in the stock client.
	corrupt := append([]byte(nil), certificates[0].DER...)
	corrupt[len(corrupt)-1] ^= 1
	certificates = append(certificates,
		stockIdentityCertificate{DER: corrupt, CA: h.srv.agentBroker.caCertDER, TrustDomain: "served.test"},
		stockIdentityCertificate{DER: certificates[0].DER, CA: h.srv.agentBroker.caCertDER, TrustDomain: "neighbor.test"})
	got := runStockIdentityChecks(t, nil, certificates)
	for i, want := range wantIDs {
		if !got.Certificates[i].Accepted || got.Certificates[i].ID != want {
			t.Errorf("stock verifier rejected/misidentified served certificate %d: %+v, want %q", i, got.Certificates[i], want)
		}
	}
	for _, rejected := range got.Certificates[len(wantIDs):] {
		if rejected.Accepted {
			t.Fatal("stock verifier accepted a broken certificate control")
		}
	}
}
