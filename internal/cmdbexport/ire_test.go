// SPDX-License-Identifier: BUSL-1.1
package cmdbexport

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/crypto/certinfo"
)

func TestIREExportUsesOnlyCertificateClassAndTenantBoundSourceKey(t *testing.T) {
	observed := time.Date(2026, 10, 28, 16, 0, 0, 0, time.UTC)
	info := certinfo.Info{SHA256Fingerprint: strings.Repeat("a", 64), CommonName: "service.example", Subject: "CN=service.example", Issuer: "CN=Issuer", SerialNumber: "01", NotBefore: observed.Add(-time.Hour), NotAfter: observed.Add(time.Hour), PublicKeyBits: 256, SignatureAlgorithm: "ECDSA-SHA256"}
	payload, err := Payload("tenant-a", "trstctl", info, "revoked", observed)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Items []struct {
			ClassName string            `json:"className"`
			Values    map[string]string `json:"values"`
			Source    struct {
				Name string `json:"source_name"`
				Key  string `json:"source_native_key"`
			} `json:"sys_object_source_info"`
		} `json:"items"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].ClassName != "cmdb_ci_certificate" {
		t.Fatalf("wrong class: %s", raw)
	}
	item := got.Items[0]
	if item.Values["fingerprint"] != info.SHA256Fingerprint || item.Values["state"] != "revoked" || item.Source.Name != "trstctl" || !strings.Contains(item.Source.Key, "tenant-a") {
		t.Fatalf("wrong certificate identity: %s", raw)
	}
	if item.Values["issuer"] != "" || item.Values["root_issuer"] != "" {
		t.Fatal("invented ServiceNow reference from a DN")
	}
	other, err := Payload("tenant-b", "trstctl", info, "revoked", observed)
	if err != nil {
		t.Fatal(err)
	}
	otherRaw, _ := json.Marshal(other)
	if string(raw) == string(otherRaw) {
		t.Fatal("source identity crossed tenant boundary")
	}
}

func TestIREEndpointCannotNameAnArbitraryTable(t *testing.T) {
	endpoint, err := Endpoint("https://example.service-now.com", "trstctl")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(endpoint)
	if u.Path != "/api/now/identifyreconcile" || u.Query().Get("sysparm_data_source") != "trstctl" {
		t.Fatal(endpoint)
	}
	for _, instance := range []string{"https://example.service-now.com/api/now/table/sys_user", "https://user:password@example.service-now.com", "https://example.service-now.com?table=sys_user", "https://example.service-now.com/#bad"} {
		if _, err := Endpoint(instance, "trstctl"); err == nil {
			t.Fatalf("accepted ambiguous instance %s", instance)
		}
	}
}
