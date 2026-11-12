// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/jose"
)

// Q3 Done-when: the crypto inventory as a CycloneDX 1.6 CBOM. After a scan of
// a TLS endpoint and a host crypto configuration, the export holds one
// cryptographic-asset component per inventory asset, with the same
// algorithms, key sizes, protocols and locations as the JSON inventory, marks
// itself incomplete and claims no compliance; its signature verifies offline
// with the audit evidence keys downloaded separately, over exactly the BOM it
// carries. (The console suite validates the encoder's golden output against
// the official CycloneDX 1.6 schema with an independent validator.)
func TestServedCBOMCycloneDXExportMatchesTheInventoryAndVerifiesOffline(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(tlsSrv.Close)
	u, err := url.Parse(tlsSrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(conf, []byte("ssl_protocols TLSv1 TLSv1.2;\nssl_ciphers DES-CBC3-SHA:ECDHE-RSA-AES128-GCM-SHA256;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	signingKey, err := jose.GenerateRSASigningKey("q3-cbom")
	if err != nil {
		t.Fatal(err)
	}
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) { d.AuditSigningKey = signingKey })
	tok := seedScopedToken(t, h.store, h.tenant, "discovery:write", "risk:read", "audit:read")
	if status, body := secretsReqKey(t, h, http.MethodPost, "/api/v1/cbom/scans", tok, "q3-cbom-scan", map[string]any{
		"tls_endpoints": []string{u.Host}, "host_configs": []string{conf},
	}); status != http.StatusCreated {
		t.Fatalf("scan = %d %s", status, body)
	}
	status, body := secretsReq(t, h, http.MethodGet, "/api/v1/cbom/assets", tok, nil)
	var inventory struct {
		Items []struct {
			ID        string `json:"id"`
			Kind      string `json:"kind"`
			Location  string `json:"location"`
			Algorithm string `json:"algorithm"`
			KeyBits   int    `json:"key_bits"`
			Protocol  string `json:"protocol"`
			Cipher    string `json:"cipher"`
		} `json:"items"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &inventory) != nil || len(inventory.Items) < 4 {
		t.Fatalf("inventory = %d %s", status, body)
	}

	status, body = secretsReq(t, h, http.MethodGet, "/api/v1/cbom/export/cyclonedx", tok, nil)
	var export struct {
		SpecVersion string          `json:"spec_version"`
		Components  int             `json:"components"`
		BOM         json.RawMessage `json:"bom"`
		BOMSHA256   string          `json:"bom_sha256"`
		SignedBOM   string          `json:"signed_bom"`
	}
	// Every inventory asset is a component; certificates, host keys,
	// libraries and observed handshakes beside them (Q3-L2) are counted too,
	// and their served shape is checked where they are reported.
	if status != http.StatusOK || json.Unmarshal(body, &export) != nil || export.SpecVersion != "1.6" ||
		export.Components < len(inventory.Items) || !strings.HasPrefix(export.BOMSHA256, "sha256:") {
		t.Fatalf("export = %d %s", status, body)
	}
	type property struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	var bom struct {
		BOMFormat    string `json:"bomFormat"`
		SpecVersion  string `json:"specVersion"`
		SerialNumber string `json:"serialNumber"`
		Metadata     struct {
			Properties []property `json:"properties"`
		} `json:"metadata"`
		Components []struct {
			Type             string `json:"type"`
			BOMRef           string `json:"bom-ref"`
			Name             string `json:"name"`
			CryptoProperties struct {
				AssetType           string `json:"assetType"`
				AlgorithmProperties *struct {
					ParameterSetIdentifier string `json:"parameterSetIdentifier"`
					Curve                  string `json:"curve"`
				} `json:"algorithmProperties"`
				ProtocolProperties *struct {
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
		} `json:"components"`
		Compositions []struct {
			Aggregate string `json:"aggregate"`
		} `json:"compositions"`
	}
	if err := json.Unmarshal(export.BOM, &bom); err != nil || bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" ||
		!strings.HasPrefix(bom.SerialNumber, "urn:uuid:") || len(bom.Compositions) != 1 || bom.Compositions[0].Aggregate != "incomplete" ||
		export.Components != len(bom.Components) {
		t.Fatalf("bom = %+v (%v); the export counts %d components", bom, err, export.Components)
	}
	if strings.Contains(strings.ToLower(string(export.BOM)), "fips") {
		t.Fatal("the CBOM must not claim FIPS")
	}
	coverage := map[string]string{}
	for _, p := range bom.Metadata.Properties {
		coverage[p.Name] = p.Value
	}
	if coverage["trstctl:coverage:assets"] != strconv.Itoa(len(inventory.Items)) || coverage["trstctl:coverage:not_covered"] == "" {
		t.Fatalf("coverage statement = %+v", coverage)
	}
	components := map[string]int{}
	for i, c := range bom.Components {
		components[c.BOMRef] = i
	}
	for _, item := range inventory.Items {
		i, ok := components[item.ID]
		if !ok {
			t.Fatalf("inventory asset %s (%s %s) is not in the CBOM", item.ID, item.Kind, item.Location)
		}
		c := bom.Components[i]
		if c.Type != "cryptographic-asset" || len(c.Evidence.Occurrences) != 1 || c.Evidence.Occurrences[0].Location != item.Location {
			t.Fatalf("component for %s = %+v", item.ID, c)
		}
		switch {
		case item.Kind == "certificate-key":
			p := c.CryptoProperties.AlgorithmProperties
			if c.CryptoProperties.AssetType != "algorithm" || p == nil {
				t.Fatalf("certificate key %s = %+v", item.ID, c.CryptoProperties)
			}
			switch strings.ToUpper(item.Algorithm) {
			case "RSA":
				if p.ParameterSetIdentifier != strconv.Itoa(item.KeyBits) || c.Name != "RSA-"+strconv.Itoa(item.KeyBits) {
					t.Fatalf("RSA key %s: CBOM %s %s, inventory %d bits", item.ID, c.Name, p.ParameterSetIdentifier, item.KeyBits)
				}
			case "ECDSA":
				if c.Name != "ECDSA-P"+strconv.Itoa(item.KeyBits) || p.Curve == "" {
					t.Fatalf("EC key %s: CBOM %s %s, inventory %d bits", item.ID, c.Name, p.Curve, item.KeyBits)
				}
			}
		case item.Cipher != "":
			pp := c.CryptoProperties.ProtocolProperties
			if pp == nil || len(pp.CipherSuites) != 1 || pp.CipherSuites[0].Name != item.Cipher {
				t.Fatalf("cipher %s = %+v", item.ID, c.CryptoProperties)
			}
		default:
			pp := c.CryptoProperties.ProtocolProperties
			if pp == nil || "TLSv"+pp.Version != item.Protocol {
				t.Fatalf("protocol %s = %+v, inventory %s", item.ID, pp, item.Protocol)
			}
		}
	}

	// Offline: the keys from the audit verification route, pinned
	// separately, verify the signature over exactly the BOM the export carries.
	status, jwks := secretsReq(t, h, http.MethodGet, "/api/v1/audit/verification-keys", tok, nil)
	if status != http.StatusOK {
		t.Fatalf("verification keys = %d %s", status, jwks)
	}
	keys, err := jose.ParseJWKSet(jwks)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := keys.VerifyArtifact(export.SignedBOM, jose.ArtifactCBOMCycloneDX)
	if err != nil {
		t.Fatalf("verify the CBOM offline: %v", err)
	}
	var signedDoc, carried any
	if json.Unmarshal(payload, &signedDoc) != nil || json.Unmarshal(export.BOM, &carried) != nil || !reflect.DeepEqual(signedDoc, carried) {
		t.Fatal("the signature does not cover the BOM the export carries")
	}
	if _, err := keys.VerifyArtifact(export.SignedBOM, jose.ArtifactCryptoReadiness); err == nil {
		t.Fatal("the CBOM signature verified as another evidence kind")
	}
}

// updateServedCycloneDX rewrites the served-export fixture the console's
// official-schema test validates (Q3-L4).
var updateServedCycloneDX = flag.Bool("update-cyclonedx-served", false,
	"rewrite internal/cbom/testdata/cyclonedx-served-export.json from the served export")

// servedCycloneDXFixture is a CycloneDX export as the API serves it, captured
// by TestServedCBOMCycloneDXExportCarriesCertificatesHostKeysLibrariesAnd
// ObservationsQ3L2, which reports every kind of component the export writes.
// web/src/__tests__/cbom_cyclonedx_schema.test.ts validates it against the
// official CycloneDX 1.6 schemas with an independent validator, beside the
// encoder's goldens.
var servedCycloneDXFixture = filepath.Join("..", "cbom", "testdata", "cyclonedx-served-export.json")

// checkServedCycloneDXFixture keeps that fixture the shape of what the API
// serves (Q3-L4): every field path and the type of its value, arrays
// collapsed, so a field the served export gains or drops fails here until the
// fixture is captured again, and then the schema test validates the new shape.
// Values (ports, serial numbers, times) differ run to run and are not compared.
func checkServedCycloneDXFixture(t *testing.T, served json.RawMessage) {
	t.Helper()
	if *updateServedCycloneDX {
		var pretty any
		if err := json.Unmarshal(served, &pretty); err != nil {
			t.Fatal(err)
		}
		// The test's scan locations are its temporary directory and a random
		// loopback port: the fixture holds fixed examples in their place.
		scrubCycloneDXLocations(pretty)
		out, err := json.MarshalIndent(pretty, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(servedCycloneDXFixture, append(out, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	fixture, err := os.ReadFile(servedCycloneDXFixture) // #nosec G304 -- the repository's own fixture path (CWE-22)
	if err != nil {
		t.Fatalf("read the served CycloneDX fixture (run with -update-cyclonedx-served): %v", err)
	}
	got, want := cycloneDXShape(t, served), cycloneDXShape(t, fixture)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the served CycloneDX export's shape is not the fixture's; capture it with -update-cyclonedx-served so the "+
			"console's official-schema test validates what is served.\nserved: %v\nfixture: %v", got, want)
	}
}

// scrubCycloneDXLocations replaces every evidence location with a fixed
// example of the same kind: a configuration file path or a host and port.
func scrubCycloneDXLocations(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if location, ok := child.(string); ok && k == "location" {
				if strings.Contains(location, "/") {
					x[k] = "/etc/nginx/nginx.conf"
				} else {
					x[k] = "app.example.test:443"
				}
				continue
			}
			scrubCycloneDXLocations(child)
		}
	case []any:
		for _, child := range x {
			scrubCycloneDXLocations(child)
		}
	}
}

// cycloneDXShape lists a JSON document's field paths with their value types.
func cycloneDXShape(t *testing.T, raw []byte) []string {
	t.Helper()
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var walk func(path string, v any)
	walk = func(path string, v any) {
		switch x := v.(type) {
		case map[string]any:
			seen[path+":object"] = true
			for k, child := range x {
				walk(path+"."+k, child)
			}
		case []any:
			seen[path+":array"] = true
			for _, child := range x {
				walk(path+"[]", child)
			}
		default:
			seen[fmt.Sprintf("%s:%T", path, v)] = true
		}
	}
	walk("$", doc)
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
