// SPDX-License-Identifier: BUSL-1.1

package cloudkeys

import "testing"

// M3-L4: a key replacement finds the source connection that reported the key
// by the host its provenance names; an unset endpoint is IAM's global one.
func TestAWSIAMEndpointNamesTheProvenanceHostM3L4(t *testing.T) {
	for _, c := range []struct{ in, endpoint, host string }{
		{"", DefaultAWSIAMEndpoint, "iam.amazonaws.com"},
		{"  https://iam.us-gov.amazonaws.com ", "https://iam.us-gov.amazonaws.com", "iam.us-gov.amazonaws.com"},
		{"http://127.0.0.1:4566", "http://127.0.0.1:4566", "127.0.0.1:4566"},
	} {
		endpoint, host, err := AWSIAMEndpoint(c.in)
		if err != nil || endpoint != c.endpoint || host != c.host {
			t.Fatalf("AWSIAMEndpoint(%q) = %q %q %v", c.in, endpoint, host, err)
		}
	}
	if _, _, err := AWSIAMEndpoint("not a url"); err == nil {
		t.Fatal("an endpoint that is not a URL was accepted")
	}
}
