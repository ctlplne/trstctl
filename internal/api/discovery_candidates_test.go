// SPDX-License-Identifier: BUSL-1.1

package api

import "testing"

// A212: only values a source recorded as a network address are candidates;
// file paths, Kubernetes references and labels are not, and nothing is resolved.
func TestCoverageCandidatesKeepOnlyNetworkAddresses(t *testing.T) {
	for value, want := range map[string]bool{
		"198.51.100.20:8443":       true,
		"[2001:db8::5]:443":        true,
		"192.0.2.7":                true,
		"api.example.test:443":     true,
		"/etc/nginx/server.crt":    false,
		"payments/tls-secret":      false,
		"https://api.example.test": false,
		"api.example.test":         false,
		"api.example.test:99999":   false,
		"":                         false,
	} {
		if got := networkAddress(value); got != want {
			t.Errorf("networkAddress(%q) = %v, want %v", value, got, want)
		}
	}
}
