// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"net/http"
	"testing"
)

// P14-L2: the MCP credential checks are opt-in by provider and refuse, at
// startup, anything but GitHub, GitLab and Slack with HTTPS endpoints and
// host-only destinations; with no provider named nothing is checked.
func TestMCPValidityFlagsAreCheckedAtStartupP14L2(t *testing.T) {
	client := &http.Client{}
	if c, err := mcpValidityChecker("/home/dev", "", "", "", client); err != nil || c != nil {
		t.Fatalf("no providers = %v %v", c, err)
	}
	c, err := mcpValidityChecker("/home/dev", "github,slack", "github=https://ghe.example.test/api/v3", "https://ghe.example.test,https://slack.com", client)
	if err != nil || c == nil || !c.Enabled("github") || !c.Enabled("slack") || c.Enabled("gitlab") || c.Enabled("aws") {
		t.Fatalf("github and slack = %v %v", c, err)
	}
	if !c.Declared("https://ghe.example.test/api/v3/user") || c.Declared("https://api.github.com/user") {
		t.Fatal("the declared destinations are not the allowlist's")
	}
	for name, flags := range map[string][4]string{
		"another provider":              {"/home/dev", "aws", "", ""},
		"a provider named twice":        {"/home/dev", "github,github", "", ""},
		"no configuration roots":        {"", "github", "", ""},
		"a plaintext endpoint":          {"/home/dev", "github", "github=http://ghe.example.test/api/v3", ""},
		"an endpoint for no provider":   {"/home/dev", "github", "gitlab=https://gitlab.example.test", ""},
		"a path in the allowlist":       {"/home/dev", "github", "", "https://api.github.com/user"},
		"endpoints without a provider":  {"/home/dev", "", "github=https://ghe.example.test/api/v3", ""},
		"an allowlist without provider": {"/home/dev", "", "", "https://api.github.com"},
	} {
		if c, err := mcpValidityChecker(flags[0], flags[1], flags[2], flags[3], client); err == nil {
			t.Fatalf("%s was accepted: %v", name, c)
		}
	}
}
