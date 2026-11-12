// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	agentdiscovery "trstctl.com/trstctl/internal/agent/discovery"
	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
)

// Q3-L2: the CycloneDX export carries what the CBOM inventory does not. A CBOM
// scan of a TLS endpoint records its certificate key; with the endpoint's
// certificate in the certificate inventory, the export holds a certificate
// component (subject, issuer, validity) whose subject public key is that key.
// A host agent's keystore key, crypto library and observed TLS 1.3 handshake
// with X25519MLKEM768 become a private-key component, a library component
// and a protocol component at their locations. The document is the shape the
// console's official-schema test validates (the served fixture, Q3-L4).
func TestServedCBOMCycloneDXExportCarriesCertificatesHostKeysLibrariesAndObservationsQ3L2(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(tlsSrv.Close)
	u, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := jose.GenerateRSASigningKey("q3l2-cbom")
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, withAgentChannel, func(d *Deps) { d.AuditSigningKey = signingKey })
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:write", "discovery:read", "risk:read", "audit:read", "certs:write", "certs:read")
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/scans", tok, "q3l2-cbom-scan", map[string]any{
		"tls_endpoints": []string{u.Host},
	}); status != http.StatusCreated {
		t.Fatalf("scan = %d %s", status, body)
	}
	// An imported EC algorithm too, so the captured shape holds every
	// algorithm field the export writes (a curve beside RSA's parameter set).
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/imports?source=vendor:q3l2-ec", tok, "q3l2-ec-import", json.RawMessage(
		`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"serialNumber":"urn:uuid:9c0d1e2f-3a4b-4c5d-8e6f-7a8b9c0d1e2f","components":[`+
			`{"type":"cryptographic-asset","bom-ref":"alg:ecdh","name":"ECDH","cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"curve":"P-256"}}}]}`)); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("import an EC algorithm = %d %s", status, body)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSrv.Certificate().Raw}))
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/certificates", tok, "q3l2-endpoint-cert", map[string]any{
		"pem": certPEM, "source": "import",
	}); status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("ingest the endpoint's certificate = %d %s", status, body)
	}

	// A host agent reports a keystore key, a crypto library and an observed handshake.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	chCtx, chCancel := context.WithCancel(context.Background())
	t.Cleanup(chCancel)
	chDone := make(chan struct{})
	go func() { defer close(chDone); h.srv.serveAgentChannel(chCtx, ln) }()
	t.Cleanup(func() { chCancel(); <-chDone })
	a := enrollAgentWithRoles(t, h, "edge-agent-q3l2", "agent.trstctl.local", []string{"host", "observer"})
	creds, err := a.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.Dial(ln.Addr().String(), creds)
	if err != nil {
		t.Fatalf("dial agent channel: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := transport.NewAgentClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	registerInventoryAgent(t, client)
	const (
		keyRef     = "/opt/q3l2/conf/keystore.p12#tomcat"
		libraryRef = "/usr/lib/q3l2/libssl.so.3"
		observed   = "10.9.8.7:443"
	)
	for _, report := range []struct {
		source  string
		finding transport.InventoryFinding
	}{
		{agentdiscovery.SourceKeystore, transport.InventoryFinding{Kind: "private_key", Ref: keyRef, Provenance: agentdiscovery.SourceKeystore + ":" + keyRef,
			Fingerprint: strings.Repeat("ab", 32), RiskScore: 85, Metadata: map[string]string{
				"material_class": "private-key", "key_format": "PKCS12", "key_algorithm": "RSA-2048", "key_size_bits": "2048",
				"encrypted": "true", "key_bytes_present": "false", "keystore_alias": "tomcat"}}},
		{agentdiscovery.SourceCryptoLibrary, transport.InventoryFinding{Kind: "crypto_library", Ref: libraryRef, Provenance: agentdiscovery.SourceCryptoLibrary + ":" + libraryRef,
			RiskScore: 50, Metadata: map[string]string{"library": "openssl", "library_version": "3.0.13", "pq_hybrid_x25519mlkem768": "no"}}},
		{agentdiscovery.SourceNetworkObserver, transport.InventoryFinding{Kind: "tls_handshake", Ref: "q3l2 " + observed + " TLSv1.3 X25519MLKEM768",
			Provenance: agentdiscovery.SourceNetworkObserver + ":eth0", RiskScore: 10, Metadata: map[string]string{
				"server": observed, "protocol": "tls", "tls_version": "TLSv1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256",
				"group": "X25519MLKEM768", "pq_hybrid": "true", "payload_stored": "false"}}},
	} {
		inv, err := client.ReportInventory(ctx, &transport.InventoryRequest{SourceKind: report.source, Findings: []transport.InventoryFinding{report.finding}})
		if err != nil || inv.Recorded != 1 || inv.Rejected != 0 {
			t.Fatalf("%s inventory: %+v, %v", report.source, inv, err)
		}
	}

	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/cbom/export/cyclonedx", tok, nil)
	var export struct {
		Components int             `json:"components"`
		BOM        json.RawMessage `json:"bom"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &export) != nil {
		t.Fatalf("export = %d %s", status, body)
	}
	type property struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type component struct {
		Type             string `json:"type"`
		BOMRef           string `json:"bom-ref"`
		Name             string `json:"name"`
		Version          string `json:"version"`
		CryptoProperties *struct {
			AssetType             string `json:"assetType"`
			CertificateProperties *struct {
				SubjectName, IssuerName, NotValidBefore, NotValidAfter, SubjectPublicKeyRef, CertificateFormat string
			} `json:"certificateProperties"`
			RelatedCryptoMaterialProperties *struct {
				Type   string `json:"type"`
				Size   int    `json:"size"`
				Format string `json:"format"`
			} `json:"relatedCryptoMaterialProperties"`
			ProtocolProperties *struct {
				Type         string `json:"type"`
				Version      string `json:"version"`
				CipherSuites []struct {
					Name string `json:"name"`
				} `json:"cipherSuites"`
			} `json:"protocolProperties"`
		} `json:"cryptoProperties"`
		Evidence struct {
			Occurrences []struct {
				Location string `json:"location"`
			} `json:"occurrences"`
		} `json:"evidence"`
		Properties []property `json:"properties"`
	}
	var bom struct {
		Metadata struct {
			Properties []property `json:"properties"`
		} `json:"metadata"`
		Components []component `json:"components"`
	}
	if err := json.Unmarshal(export.BOM, &bom); err != nil || export.Components != len(bom.Components) {
		t.Fatalf("export lists %d components, the BOM %d (%v)", export.Components, len(bom.Components), err)
	}
	at := func(c component, location string) bool {
		for _, o := range c.Evidence.Occurrences {
			if o.Location == location {
				return true
			}
		}
		return false
	}
	propertyOf := func(c component, name string) string {
		for _, p := range c.Properties {
			if p.Name == name {
				return p.Value
			}
		}
		return ""
	}
	byRef := map[string]component{}
	var certificate, key, library, handshake *component
	for i := range bom.Components {
		c := bom.Components[i]
		byRef[c.BOMRef] = c
		switch {
		case c.CryptoProperties != nil && c.CryptoProperties.AssetType == "certificate" && at(c, u.Host):
			certificate = &bom.Components[i]
		case c.CryptoProperties != nil && c.CryptoProperties.AssetType == "related-crypto-material" && at(c, keyRef):
			key = &bom.Components[i]
		case c.Type == "library" && at(c, libraryRef):
			library = &bom.Components[i]
		case c.CryptoProperties != nil && c.CryptoProperties.AssetType == "protocol" && strings.HasPrefix(c.BOMRef, "observed:") && at(c, observed):
			handshake = &bom.Components[i]
		}
	}
	if certificate == nil {
		t.Fatal("no certificate component for the scanned endpoint's certificate")
	}
	cp := certificate.CryptoProperties.CertificateProperties
	keyComponent, ok := byRef[cp.SubjectPublicKeyRef]
	if !ok || keyComponent.CryptoProperties == nil || keyComponent.CryptoProperties.AssetType != "algorithm" || !at(keyComponent, u.Host) ||
		cp.CertificateFormat != "X.509" || cp.NotValidAfter == "" || cp.NotValidBefore == "" || cp.IssuerName == "" ||
		!strings.HasPrefix(certificate.BOMRef, "certificate:") {
		t.Fatalf("certificate = %+v; its key %s = %+v", cp, cp.SubjectPublicKeyRef, keyComponent)
	}
	if key == nil || key.CryptoProperties.RelatedCryptoMaterialProperties.Type != "private-key" ||
		key.CryptoProperties.RelatedCryptoMaterialProperties.Size != 2048 || key.CryptoProperties.RelatedCryptoMaterialProperties.Format != "PKCS12" ||
		propertyOf(*key, "trstctl:public_key_fingerprint") != strings.Repeat("ab", 32) {
		t.Fatalf("keystore key = %+v", key)
	}
	if library == nil || library.Name != "openssl" || library.Version != "3.0.13" || propertyOf(*library, "trstctl:pq_hybrid_x25519mlkem768") != "no" {
		t.Fatalf("library = %+v", library)
	}
	if handshake == nil || handshake.CryptoProperties.ProtocolProperties.Type != "tls" || handshake.CryptoProperties.ProtocolProperties.Version != "1.3" ||
		len(handshake.CryptoProperties.ProtocolProperties.CipherSuites) != 1 || handshake.CryptoProperties.ProtocolProperties.CipherSuites[0].Name != "TLS_AES_128_GCM_SHA256" ||
		propertyOf(*handshake, "trstctl:key_exchange_group") != "X25519MLKEM768" || propertyOf(*handshake, "trstctl:pq_hybrid") != "true" {
		t.Fatalf("observed handshake = %+v", handshake)
	}
	coverage := map[string]string{}
	for _, p := range bom.Metadata.Properties {
		coverage[p.Name] = p.Value
	}
	for _, class := range []string{"certificates", "host_keys", "libraries", "observed_handshakes"} {
		if n := coverage["trstctl:coverage:"+class]; n == "" || n == "0" {
			t.Fatalf("coverage %s = %q; want at least the reported one (%v)", class, n, coverage)
		}
	}
	checkServedCycloneDXFixture(t, export.BOM)
}
