// SPDX-License-Identifier: BUSL-1.1
package adcs

import (
	"net/url"
	"strings"
	"testing"
)

func FuzzLDAPEndpointProbeHostname(f *testing.F) {
	for _, seed := range []string{"ca01.corp.example", "CA01.CORP.EXAMPLE.", "corp.example.attacker.test", "127.0.0.1", "169.254.169.254", "ca.corp.example@metadata", "https://ca.corp.example/", "*.corp.example", "ca\n.corp.example", "ca.κorp.example"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, hostname string) {
		intent := InventoryIntent{EndpointProbe: &EndpointProbeOptions{Enabled: true, DNSSuffixes: []string{"corp.example"}}}
		page, err := PlanEnrollmentEndpointProbes(intent, []EnrollmentService{{Name: "CA", DNSName: hostname}})
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Targets) == 0 {
			if len(page.HostIssues) != 1 || page.Complete {
				t.Fatal("invalid hostname silently became complete")
			}
			return
		}
		if len(page.Targets) != 4 || len(page.HostIssues) != 0 {
			t.Fatal("hostname escaped the fixed candidate count")
		}
		for _, target := range page.Targets {
			parsed, err := url.Parse(target.URL)
			if err != nil {
				t.Fatal(err)
			}
			host := parsed.Hostname()
			if parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" || parsed.Fragment != "" || (host != "corp.example" && !strings.HasSuffix(host, ".corp.example")) || (parsed.Path != "/certsrv/" && parsed.Path != "/certsrv/mscep/mscep.dll") || (parsed.Scheme != "http" && parsed.Scheme != "https") {
				t.Fatalf("untrusted hostname escaped its grant: %q -> %s", hostname, target.URL)
			}
		}
	})
}
