// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/authz"
)

func TestPrivacySubjectErasureBindingCoversCallerRouteSubjectAndReason(t *testing.T) {
	request := func(subject, method, path string) *http.Request {
		r := httptest.NewRequest(method, path, nil)
		return r.WithContext(context.WithValue(
			r.Context(),
			principalCtxKey,
			authz.Principal{Subject: subject},
		))
	}
	const path = "/api/v1/privacy/subject-erasures"
	command := privacySubjectErasureRequest{
		Subject: "alice@example.com",
		Reason:  "data subject request",
	}
	base, err := privacySubjectErasureRequestBinding(
		request("operator-a", http.MethodPost, path),
		command,
	)
	if err != nil {
		t.Fatal(err)
	}
	same, err := privacySubjectErasureRequestBinding(
		request("operator-a", http.MethodPost, path),
		command,
	)
	if err != nil {
		t.Fatal(err)
	}
	if same != base {
		t.Fatalf("same canonical privacy command changed binding: %s != %s", same, base)
	}

	changedSubject := command
	changedSubject.Subject = "bob@example.com"
	changedReason := command
	changedReason.Reason = "corrected request"
	cases := map[string]struct {
		request *http.Request
		command privacySubjectErasureRequest
	}{
		"subject": {request("operator-a", http.MethodPost, path), changedSubject},
		"reason":  {request("operator-a", http.MethodPost, path), changedReason},
		"caller":  {request("operator-b", http.MethodPost, path), command},
		"method":  {request("operator-a", http.MethodPut, path), command},
		"path":    {request("operator-a", http.MethodPost, path+"/"), command},
	}
	for name, tc := range cases {
		got, err := privacySubjectErasureRequestBinding(tc.request, tc.command)
		if err != nil {
			t.Fatalf("%s binding: %v", name, err)
		}
		if got == base {
			t.Errorf("changed %s did not change durable privacy binding", name)
		}
	}
}
