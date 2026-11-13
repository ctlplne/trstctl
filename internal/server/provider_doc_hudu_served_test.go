// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"strconv"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/docsys/docsystest"
)

// MSP-15 Done-when (served, Hudu stand-in written from the calls Hudu's
// published API clients make): the shared documentation record proof — each
// customer's inventory in one asset under its own Hudu company only, with the
// count, next expiry and link; no second asset after a lost answer; nothing
// written while unchanged; a renewal updating the asset in place; an asset
// deleted in Hudu written again; the API key in neither the debug log nor
// the outbox.
func TestServedHuduKeepsEachCustomersCertificateRecordMSP15(t *testing.T) {
	const key = "hudu-served-api-key" // #nosec G101 -- a test-only value (CWE-798)
	hu := docsystest.NewHudu(key)
	t.Cleanup(hu.Close)
	hu.AddCompany(31)
	hu.AddCompany(32)
	hu.AddLayout(7, "certificates", "next_expiry", "certificate_count", "trstctl_link")
	runDocRecordProof(t, docProofCase{
		target: config.ProviderBillingTarget{ID: "hudu", Type: "hudu", Endpoint: hu.URL(), AllowInsecureLoopback: true,
			Hudu: &config.HuduTarget{APIKeyRef: writeServedCredentialFile(t, "hudu-key", key), AssetLayoutID: 7,
				Fields:     config.HuduFields{Inventory: "certificates", NextExpiry: "next_expiry", Count: "certificate_count", Link: "trstctl_link"},
				ConsoleURL: "https://trstctl.msp.example"}},
		secret: key, orgA: "31", orgB: "32",
		records: func() []docProofRecord {
			var out []docProofRecord
			for _, a := range hu.Assets() {
				inventory, _ := a.Fields["certificates"].(string)
				count, _ := a.Fields["certificate_count"].(float64)
				next, _ := a.Fields["next_expiry"].(string)
				link, _ := a.Fields["trstctl_link"].(string)
				out = append(out, docProofRecord{ID: strconv.FormatInt(a.ID, 10), Org: strconv.FormatInt(a.CompanyID, 10), Inventory: inventory,
					Count: count, NextExpiry: next, Link: link})
			}
			return out
		},
		remove: func(id string) {
			n, _ := strconv.ParseInt(id, 10, 64)
			hu.DeleteAsset(n)
		},
		failWrites: hu.FailWritesAfterApplying,
		writes:     func() int { _, writes, _ := hu.Counts(); return writes },
	})
}
