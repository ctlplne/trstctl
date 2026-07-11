// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

func TestRightSizeBindingCoversCallerExactPathAndCanonicalCommand(t *testing.T) {
	request := func(subject, path string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, path, nil)
		r = r.WithContext(context.WithValue(r.Context(), principalCtxKey, authz.Principal{Subject: subject}))
		return r
	}
	command := remediationPlaybookRunRequest{
		TargetIdentityID: " identity-1 ", Connector: " aws-iam ", Target: " role-1 ",
		RemoveScopes: []string{"Write", " admin:* ", "write"},
	}
	base, err := rightSizeRequestBinding(request("operator-a", "/api/v1/remediation/playbooks/nhi-right-size/runs"), canonicalRightSizePlaybookCommand(command))
	if err != nil {
		t.Fatal(err)
	}
	reordered := command
	reordered.RemoveScopes = []string{"ADMIN:*", "write"}
	same, err := rightSizeRequestBinding(request("operator-a", "/api/v1/remediation/playbooks/nhi-right-size/runs"), canonicalRightSizePlaybookCommand(reordered))
	if err != nil {
		t.Fatal(err)
	}
	if same != base {
		t.Fatalf("semantically identical scope selection changed binding: %s != %s", same, base)
	}

	changedBody := command
	changedBody.Target = "role-2"
	changedBodyBinding, _ := rightSizeRequestBinding(request("operator-a", "/api/v1/remediation/playbooks/nhi-right-size/runs"), canonicalRightSizePlaybookCommand(changedBody))
	changedCaller, _ := rightSizeRequestBinding(request("operator-b", "/api/v1/remediation/playbooks/nhi-right-size/runs"), canonicalRightSizePlaybookCommand(command))
	changedPath, _ := rightSizeRequestBinding(request("operator-a", "/api/v1/remediation/playbooks/nhi-right-size/runs/"), canonicalRightSizePlaybookCommand(command))
	for name, got := range map[string]string{
		"body": changedBodyBinding, "caller": changedCaller, "exact path": changedPath,
	} {
		if got == base {
			t.Errorf("changed %s did not change durable binding", name)
		}
	}
}
