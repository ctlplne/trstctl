// SPDX-License-Identifier: BUSL-1.1

package awsiamkeys

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// M3-L4: a key replacement sets the key Inactive with one signed IAM
// UpdateAccessKey naming the user and the key; IAM's refusals come back as a
// StatusError carrying only the status, never the response body.
func TestDeactivateKeySendsOneSignedUpdateAccessKeyM3L4(t *testing.T) {
	var forms []url.Values
	var auth []string
	answer := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(raw))
		forms = append(forms, form)
		auth = append(auth, r.Header.Get("Authorization"))
		if answer != http.StatusOK {
			http.Error(w, "<ErrorResponse><Error><Code>NoSuchEntity</Code><Message>user m3l4-bot</Message></Error></ErrorResponse>", answer)
			return
		}
		_, _ = io.WriteString(w, `<UpdateAccessKeyResponse><ResponseMetadata><RequestId>m3l4</RequestId></ResponseMetadata></UpdateAccessKeyResponse>`)
	}))
	t.Cleanup(srv.Close)
	const signing = "m3l4-unit-signing-value" // #nosec G101 -- fabricated fixture signing value; no value is real (CWE-798)
	r, err := New(Config{Endpoint: srv.URL, AccessKeyID: "m3l4-operator", SecretAccessKey: signing, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.DeactivateKey(t.Context(), "m3l4-bot", "m3l4-key-stale"); err != nil {
		t.Fatal(err)
	}
	if len(forms) != 1 {
		t.Fatalf("requests = %d; want one", len(forms))
	}
	f := forms[0]
	if f.Get("Action") != "UpdateAccessKey" || f.Get("UserName") != "m3l4-bot" || f.Get("AccessKeyId") != "m3l4-key-stale" ||
		f.Get("Status") != "Inactive" || f.Get("Version") != "2010-05-08" {
		t.Fatalf("UpdateAccessKey form = %v", f)
	}
	if !strings.HasPrefix(auth[0], "AWS4-HMAC-SHA256 Credential=m3l4-operator/") || strings.Contains(auth[0], signing) {
		t.Fatalf("authorization = %q; want a SigV4 signature that carries no signing value", auth[0])
	}
	for _, status := range []int{http.StatusNotFound, http.StatusServiceUnavailable} {
		answer = status
		err := r.DeactivateKey(t.Context(), "m3l4-bot", "m3l4-key-stale")
		var se *StatusError
		if !errors.As(err, &se) || se.Status != status || se.Action != "UpdateAccessKey" || strings.Contains(err.Error(), "NoSuchEntity") {
			t.Fatalf("IAM answering %d = %v; want a StatusError with the status and no response body", status, err)
		}
	}
	if err := r.DeactivateKey(t.Context(), "", "m3l4-key-stale"); err == nil {
		t.Fatal("a deactivation without a user was sent")
	}
}
