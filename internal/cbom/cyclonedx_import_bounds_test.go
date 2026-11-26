// SPDX-License-Identifier: BUSL-1.1

package cbom_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/cbom"
)

func TestCycloneDXImportRejectsCipherSuiteOccurrenceProduct(t *testing.T) {
	raw := protocolBOM(t, 225, 225, false)
	if len(raw) > 1<<20 {
		t.Fatalf("regression BOM unexpectedly large: %d bytes", len(raw))
	}
	if _, err := cbom.ParseCycloneDXImport(raw, "vendor:bounded", cbom.DefaultPolicy()); err == nil || !strings.Contains(err.Error(), "findings") {
		t.Fatalf("more than 50,000 output findings accepted: %v", err)
	}
}

func TestCycloneDXImportBoundsIndividualExpansionLists(t *testing.T) {
	for name, dimensions := range map[string][2]int{
		"occurrences":   {257, 1},
		"cipher suites": {1, 257},
	} {
		t.Run(name, func(t *testing.T) {
			raw := protocolBOM(t, dimensions[0], dimensions[1], false)
			if _, err := cbom.ParseCycloneDXImport(raw, "vendor:bounded", cbom.DefaultPolicy()); err == nil {
				t.Fatal("component exceeded the per-list expansion bound")
			}
		})
	}
}

func TestCycloneDXImportDeduplicatesEvidenceLocations(t *testing.T) {
	raw := protocolBOM(t, 2, 2, true)
	bom, err := cbom.ParseCycloneDXImport(raw, "vendor:bounded", cbom.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if len(bom.Findings) != 6 {
		t.Fatalf("got %d findings, want two unique locations x protocol and two suites", len(bom.Findings))
	}
}

func TestCycloneDXImportRejectsEmptyCipherSuite(t *testing.T) {
	raw := protocolBOM(t, 1, 1, false)
	raw = []byte(strings.Replace(string(raw), `"name":"suite-0"`, `"name":""`, 1))
	if _, err := cbom.ParseCycloneDXImport(raw, "vendor:bounded", cbom.DefaultPolicy()); err == nil {
		t.Fatal("empty cipher suite name was accepted")
	}
}

func protocolBOM(t *testing.T, occurrences, suites int, duplicate bool) []byte {
	t.Helper()
	locations := make([]map[string]any, 0, occurrences+1)
	for i := 0; i < occurrences; i++ {
		locations = append(locations, map[string]any{"location": fmt.Sprintf("src/%d", i)})
	}
	if duplicate {
		locations = append(locations, map[string]any{"location": "src/0"})
	}
	ciphers := make([]map[string]any, suites)
	for i := range ciphers {
		ciphers[i] = map[string]any{"name": fmt.Sprintf("suite-%d", i)}
	}
	component := map[string]any{
		"type": "cryptographic-asset", "bom-ref": "proto:tls", "name": "TLS",
		"evidence": map[string]any{"occurrences": locations},
		"cryptoProperties": map[string]any{
			"assetType": "protocol", "protocolProperties": map[string]any{
				"type": "tls", "version": "1.2", "cipherSuites": ciphers,
			},
		},
	}
	raw, err := json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []any{component}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
