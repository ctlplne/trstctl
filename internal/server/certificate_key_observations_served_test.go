// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/mtls"
)

// A121: a certificate trstctl did not issue reads as custody "not recorded",
// and that stays true. What a host agent's private-key inventory can add is an
// observation: a key file whose public key matches the certificate was seen on
// that host at that path, with its mode and encryption. The certificate detail
// lists it (metadata only, from the agent's own report, named by the agent's
// certificate), and never turns it into a custody claim.
func TestServedCertificateDetailListsWhereAMatchingKeyWasSeen(t *testing.T) {
	ctx := context.Background()
	h := newServedHarnessWithEventOptions(t, config.Protocols{}, nil, withAgentChannel)
	registerServedTenant(t, h, "Key observation tenant")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })
	host := enrollKRLAgent(t, h, ln.Addr().String(), "web-1", []string{mtls.AgentRoleHost})
	if _, err := host.client.Heartbeat(ctx, &transport.HeartbeatRequest{Status: "active", Version: "a121"}); err != nil {
		t.Fatal(err)
	}

	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "A121 Outside CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var leaves [][]byte
	for _, name := range []string{"seen.a121.example", "unseen.a121.example"} {
		key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Destroy)
		csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: name}, key)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := crypto.SignLeafFromCSRWithProfile(caDER, caKey, csr, time.Hour, crypto.LeafProfile{})
		if err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, leaf)
	}
	seen, err := certinfo.Inspect(leaves[0])
	if err != nil {
		t.Fatal(err)
	}
	// The agent's private-key inventory, as the shipped agent reports it.
	resp, err := host.client.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: "private-key", Findings: []transport.InventoryFinding{{
		Kind: "private_key", Ref: "/etc/ssl/private/seen.key", Provenance: "private-key:/etc/ssl/private/seen.key",
		Fingerprint: seen.SPKISHA256, RiskScore: 85,
		Metadata: map[string]string{"material_class": "private-key", "key_format": "PKCS8", "key_algorithm": "ECDSA-P256",
			"fingerprint_basis": "public-spki-sha256", "encrypted": "false", "key_bytes_present": "false",
			"file_mode_restricted": "true", "file_mode": "0600", "source_classification": "private-key"},
	}}})
	if err != nil || resp.Recorded != 1 {
		t.Fatalf("private-key report = %+v (%v)", resp, err)
	}

	token := seedScopedToken(t, h.store, h.tenant, "certs:read", "certs:write")
	type keyObservation struct {
		Agent     string `json:"agent"`
		Path      string `json:"path"`
		FileMode  string `json:"file_mode"`
		Encrypted bool   `json:"encrypted"`
		KeyFormat string `json:"key_format"`
	}
	detail := func(der []byte, key string) (string, []keyObservation) {
		t.Helper()
		status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates", token, key,
			map[string]any{"pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))})
		var created struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &created) != nil {
			t.Fatalf("ingest = %d %s", status, body)
		}
		status, body = secretsReq(t, h, http.MethodGet, "/api/v1/certificates/"+created.ID, token, nil)
		var got struct {
			KeyOrigin       string           `json:"key_origin"`
			KeyObservations []keyObservation `json:"key_observations"`
		}
		if status != http.StatusOK || json.Unmarshal(body, &got) != nil {
			t.Fatalf("certificate detail = %d %s", status, body)
		}
		return got.KeyOrigin, got.KeyObservations
	}
	origin, observations := detail(leaves[0], "a121-seen")
	if origin != "" || len(observations) != 1 || observations[0].Agent != "web-1" || observations[0].Path != "/etc/ssl/private/seen.key" ||
		observations[0].FileMode != "0600" || observations[0].Encrypted || observations[0].KeyFormat != "PKCS8" {
		t.Fatalf("seen certificate: origin %q observations %+v, want unrecorded custody and one observation on web-1", origin, observations)
	}
	if _, observations := detail(leaves[1], "a121-unseen"); len(observations) != 0 {
		t.Fatalf("unseen certificate observations = %+v, want none", observations)
	}
}
