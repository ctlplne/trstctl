// SPDX-License-Identifier: BUSL-1.1
package assessment

import (
	"encoding/json"
	"testing"
	"time"
	"trstctl.com/trstctl/internal/cloudentitlements/awsiam"
)

func TestAuthorityFingerprintIgnoresUsageAndReceiptOrderButBindsNativeRulesA264(t *testing.T) {
	identity := awsiam.Identity{NativeID: "AROAOWNED", TrustDocument: json.RawMessage(`{"b":1,"a":2}`), PolicyReceipts: []awsiam.PolicyReceipt{{ID: "b", Category: "inline", SHA256: "second"}, {ID: "a", Category: "managed", Version: "v2", SHA256: "first"}}}
	first, err := AuthorityFingerprint(identity)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	identity.LastUsed = &now
	identity.TrustDocument = json.RawMessage(`{"a":2,"b":1}`)
	identity.PolicyReceipts[0], identity.PolicyReceipts[1] = identity.PolicyReceipts[1], identity.PolicyReceipts[0]
	same, err := AuthorityFingerprint(identity)
	if err != nil || same != first {
		t.Fatal("usage or object/list ordering invalidated unchanged native authority")
	}
	identity.PolicyReceipts[0].Version = "v3"
	changed, err := AuthorityFingerprint(identity)
	if err != nil || changed == first {
		t.Fatal("native policy version drift kept the approval fingerprint")
	}
}
