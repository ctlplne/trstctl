// SPDX-License-Identifier: BUSL-1.1

package config

import "testing"

func TestCMDBCertificateWriterNeedsItsOwnTenantBoundAuthority(t *testing.T) {
	const writerRef = "secret://cmdb/writer"
	valid := CMDBCertificateExportBinding{ID: "certificates", TenantID: "11111111-1111-1111-1111-111111111111", InstanceURL: "https://cmdb.example.test", TokenRef: writerRef, DataSource: "trstctl"}
	if errs := ValidateCMDBCertificateExports([]CMDBCertificateExportBinding{valid}); len(errs) > 0 {
		t.Fatal(errs)
	}
	if valid.Enabled {
		t.Fatal("write authority enabled by default")
	}
	for name, change := range map[string]func(*CMDBCertificateExportBinding){
		"tenant":        func(b *CMDBCertificateExportBinding) { b.TenantID = "" },
		"source":        func(b *CMDBCertificateExportBinding) { b.DataSource = "" },
		"credential":    func(b *CMDBCertificateExportBinding) { b.TokenRef = "inline-value" },
		"table path":    func(b *CMDBCertificateExportBinding) { b.InstanceURL += "/api/now/table/cmdb_ci" },
		"http":          func(b *CMDBCertificateExportBinding) { b.InstanceURL = "http://10.0.0.1" },
		"private flag":  func(b *CMDBCertificateExportBinding) { b.AllowPrivateEndpoint = true },
		"private range": func(b *CMDBCertificateExportBinding) { b.PrivateEgressCIDRs = []string{"10.0.0.0/8"} },
		"wildcard": func(b *CMDBCertificateExportBinding) {
			b.AllowPrivateEndpoint = true
			b.PrivateEgressCIDRs = []string{"0.0.0.0/0"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := valid
			change(&bad)
			if errs := ValidateCMDBCertificateExports([]CMDBCertificateExportBinding{bad}); len(errs) == 0 {
				t.Fatal("invalid write binding accepted")
			}
		})
	}
	if errs := ValidateCMDBCertificateExports([]CMDBCertificateExportBinding{valid, valid}); len(errs) == 0 {
		t.Fatal("ambiguous duplicate binding accepted")
	}
}
