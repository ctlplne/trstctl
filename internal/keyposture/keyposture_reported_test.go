// SPDX-License-Identifier: BUSL-1.1

package keyposture

import "testing"

const emSignECCRootG3SPKI = "8d417db2dd8bf5e3084d1e3f196d583849d81bdd4c00c70b9d39369e96b8c782"

// What a reporter sent is matched against the server's own list: by key
// hash (a trust-store root), by authority key identifier (a leaf under an
// intermediate), by issuer name; and a reporter's own distrust claim never
// survives the merge, while its weak-key reasons do.
func TestRateReportedIdentityAndMergeReported(t *testing.T) {
	if v := RateReportedIdentity(emSignECCRootG3SPKI, "", "", ""); v.DistrustEntry != "emSign ECC Root CA - G3" || v.DistrustHow != "itself" {
		t.Fatalf("root by SPKI: %+v", v)
	}
	if v := RateReportedIdentity("", "", "34:EA:EA:0C:EB:C9:0A:DA:F9:D0:C5:E2:ED:9B:78:C9:87:9E:1B:6C", "CN=EM OV TLS CA - G3C"); v.DistrustHow != "issuer_key_id" {
		t.Fatalf("leaf by key identifier: %+v", v)
	}
	if v := RateReportedIdentity("", "", "", "CN=EM EV TLS CA - G3C,O=eMudhra Inc,C=US"); v.DistrustHow != DistrustedByName {
		t.Fatalf("leaf by issuer name: %+v", v)
	}
	if v := RateReportedIdentity("", "", "", ""); !v.Empty() {
		t.Fatalf("nothing reported, yet rated: %+v", v)
	}
	// A report that claims a distrust the server does not see loses the claim
	// and keeps its weak-key reasons, risk raised to the weak floor.
	claimed := map[string]string{"spki_sha256": "aa", MetaDistrustEntry: "Made Up CA", MetaDistrustHow: "itself", MetaKeyStrength: "weak", MetaWeakKeyReason: "RSA-1024 is below the 2048-bit minimum"}
	out, risk := MergeReported(claimed, Verdict{}, 20)
	if out[MetaDistrustEntry] != "" || out[MetaKeyStrength] != "weak" || risk != RiskWeak || out["spki_sha256"] != "aa" {
		t.Fatalf("merged %v risk %d", out, risk)
	}
	out, risk = MergeReported(map[string]string{}, RateReportedIdentity(emSignECCRootG3SPKI, "", "", ""), 20)
	if out[MetaDistrustEntry] != "emSign ECC Root CA - G3" || risk != RiskDistrusted {
		t.Fatalf("server verdict merged %v risk %d", out, risk)
	}
}
