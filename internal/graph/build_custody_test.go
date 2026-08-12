// SPDX-License-Identifier: MPL-2.0

package graph

import (
	"testing"

	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/store"
)

func TestCertificateNodeCarriesCanonicalCustodyIntoEvidenceGraphAUD25(t *testing.T) {
	t.Parallel()
	node := certificateNode(store.Certificate{
		ID: "cert-7", Subject: "api.example.test", Fingerprint: "sha256:cert-7", Status: "active", Serial: "07",
		KeyOrigin: string(custody.OriginHostAgent), KeyStorage: string(custody.StorageFile),
		KeyExportable: string(custody.Exportable), KeyGeneratedBy: "host-agent-7",
	})
	for key, want := range map[string]string{
		"credential_kind": "certificate", "certificate_id": "cert-7",
		"fingerprint": "sha256:cert-7", "subject": "api.example.test",
		"key_origin": "host_agent", "key_storage": "file",
		"key_exportable": "exportable", "key_generated_by": "host-agent-7",
	} {
		if got := node.Attrs[key]; got != want {
			t.Errorf("certificate graph attribute %s = %q, want %q", key, got, want)
		}
	}
}
