package cli

import (
	"strings"
	"testing"
)

func TestAgentEnrollTokenBuildsOptionalPinnedIdentityBody(t *testing.T) {
	var cmd Command
	for _, c := range Commands() {
		if strings.Join(c.Name, " ") == "agents enroll-token" {
			cmd = c
			break
		}
	}
	if len(cmd.Name) == 0 {
		t.Fatal("agents enroll-token command not registered")
	}

	path, _, body, _, err := buildRequest(cmd, nil, strings.NewReader(""))
	if err != nil {
		t.Fatalf("build no-body enroll-token: %v", err)
	}
	if path != "/api/v1/agents/enrollment-tokens" {
		t.Fatalf("path = %q, want /api/v1/agents/enrollment-tokens", path)
	}
	if body != nil {
		t.Fatalf("no-body enroll-token body = %q, want nil", body)
	}

	want := `{"allowed_identity":"node-a"}`
	_, _, body, _, err = buildRequest(cmd, []string{"-f", "-"}, strings.NewReader(want))
	if err != nil {
		t.Fatalf("build pinned enroll-token: %v", err)
	}
	if strings.TrimSpace(string(body)) != want {
		t.Fatalf("pinned enroll-token body = %q, want %q", body, want)
	}
}
