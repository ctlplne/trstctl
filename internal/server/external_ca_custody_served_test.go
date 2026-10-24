// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/digicert/digicertfake"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/custody"
)

// A121: a certificate ordered through an external CA was recorded with no
// custody at all, although the route requires the caller's own CSR and the
// control plane generates nothing — the same facts that make every enrollment
// protocol record key_origin=requester. The issuance service now records the
// origin its caller states; storage and exportability stay unrecorded because a
// CSR does not establish them.
func TestServedExternalCAIssuanceRecordsRequesterCustody(t *testing.T) {
	dc, err := digicertfake.NewServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dc.Close)
	h := newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		d.APIOptions = append(d.APIOptions, api.WithInsecureHeaderResolver())
		d.ExternalCAs = []ExternalCA{
			{ID: "digicert", Type: "digicert", CA: digicert.New("digicert", dc.URL(), []byte(dc.APIKey()), digicert.WithHTTPClient(&http.Client{Timeout: 5 * time.Second}))},
		}
	})
	issued := issueExternalCAWithBody(t, h, "digicert", "a121-digicert", externalCAIssueRequestBody(t, "svc.a121.served.test"))
	info, err := certinfo.Inspect([]byte(issued.CertificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := h.store.GetCertificateByFingerprint(context.Background(), h.tenant, info.SHA256Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if stored.KeyOrigin != string(custody.OriginRequester) || stored.KeyStorage != "" || stored.KeyExportable != "" {
		t.Fatalf("external CA custody = origin %q storage %q exportable %q, want requester with storage and exportability unrecorded",
			stored.KeyOrigin, stored.KeyStorage, stored.KeyExportable)
	}
}
