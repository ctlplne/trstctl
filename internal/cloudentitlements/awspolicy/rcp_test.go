// SPDX-License-Identifier: BUSL-1.1
package awspolicy

import "testing"

func TestAWSRCPNativeSyntaxA264(t *testing.T) {
	request, evidence := basicRequest(), knownEvidence()
	evidence.Identity.Documents = []Document{parsed(t, "allow", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)}
	for _, body := range []string{
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"*","Resource":"*"}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Principal":"*","NotAction":"s3:PutObject","Resource":"*"}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Deny","NotPrincipal":{"AWS":"111122223333"},"Action":"s3:GetObject","Resource":"*"}}`,
	} {
		document, err := Parse("unsupported-rcp", []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		evidence.RCPCoverage = Complete
		evidence.RCP = []PolicySet{{Coverage: Complete, Documents: []Document{document}}}
		if got := Evaluate(request, evidence); got.Decision != Indeterminate {
			t.Fatalf("unsupported native RCP syntax must remain indeterminate: %s %+v", body, got)
		}
	}
}
