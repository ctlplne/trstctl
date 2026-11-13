// SPDX-License-Identifier: BUSL-1.1

package api

import "testing"

// M3-L4: the replacement is refused unless the finding's source still reads
// an aws-iam connection at the host that reported the key.
func TestSourceHasAWSIAMConnectionMatchesTheReportingHostM3L4(t *testing.T) {
	config := []byte(`{"providers":[{"provider":"gcp-iam","endpoint":"https://iam.googleapis.com"},` +
		`{"provider":"aws-iam"},{"provider":"aws-iam","endpoint":"http://127.0.0.1:4566"}]}`)
	for host, want := range map[string]bool{
		"iam.amazonaws.com":  true,
		"127.0.0.1:4566":     true,
		"iam.googleapis.com": false,
		"iam.example.net":    false,
	} {
		if got := sourceHasAWSIAMConnection(config, host); got != want {
			t.Fatalf("host %s = %v; want %v", host, got, want)
		}
	}
	if sourceHasAWSIAMConnection([]byte(`not json`), "iam.amazonaws.com") {
		t.Fatal("a configuration that is not JSON matched")
	}
}
