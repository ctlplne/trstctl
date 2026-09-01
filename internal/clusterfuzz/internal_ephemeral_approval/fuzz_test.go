// SPDX-License-Identifier: MPL-2.0

package clusterfuzz

import (
	"strings"
	"testing"

	ephemeral "trstctl.com/trstctl/internal/ephemeral"
)

const approvalTestTenant = "11111111-1111-4111-8111-111111111111"

func FuzzSubjectFromSPIFFEID(f *testing.F) {
	const prefix = "spiffe://approval.test/_trstctl/v1/tenant/" + approvalTestTenant + "/ephemeral/method/k8s_sat/subject/"
	for _, seed := range []string{
		"", "spiffe://approval.test/ns/default/sa/web",
		"spiffe://approval.test/repo:org/project%3Fref=main",
		"spiffe://approval.test/a%252Fb", "spiffe://approval.test/%C3%A9",
		"spiffe://approval.test/a%2Fb", "spiffe://approval.test/x/../_trstctl/old:name",
		prefix + "ns/default/sa/web", prefix + "trstctl-hex-613a62",
		prefix + "trstctl-hex-612f62", prefix + "trstctl-hex-776562", prefix + "repo%3Aorg",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		subject, err := ephemeral.SubjectFromSPIFFEID(raw)
		if err != nil {
			return
		}
		if subject == "" {
			t.Fatal("accepted empty attestation subject")
		}
		for _, part := range strings.Split(subject, "/") {
			if part == "" || part == "." || part == ".." {
				t.Fatal("accepted ambiguous subject hierarchy")
			}
		}
		if again, err := ephemeral.SubjectFromSPIFFEID(raw); err != nil || again != subject {
			t.Fatal("subject decoder changed its result")
		}
	})
}
