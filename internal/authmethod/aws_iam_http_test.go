// SPDX-License-Identifier: MPL-2.0

package authmethod

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestHTTPSignedSTSClientRejectsSchemeDowngrade(t *testing.T) {
	client := HTTPSignedSTSClient{Endpoint: "https://sts.example.test/"}
	credential := []byte(`{"method":"GET","url":"http://sts.example.test/?Action=GetCallerIdentity&X-Amz-Signature=fake"}`) // #nosec G101 -- fabricated signed-request fixture (CWE-798)
	if _, err := client.GetCallerIdentity(context.Background(), credential); err == nil {
		t.Fatal("signed STS request with a downgraded scheme was accepted")
	}
}

func TestHTTPSignedSTSClientDoesNotFollowRedirects(t *testing.T) {
	var redirected atomic.Int32
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", sink.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer sts.Close()

	client := HTTPSignedSTSClient{Endpoint: sts.URL, HTTPClient: sts.Client()}
	credential := []byte(fmt.Sprintf(`{"method":"GET","url":%q,"headers":{"Authorization":["AWS4-HMAC-SHA256 Credential=fake"]}}`, sts.URL+"/?Action=GetCallerIdentity")) // #nosec G101 -- fabricated signed-request fixture (CWE-798)
	if _, err := client.GetCallerIdentity(context.Background(), credential); err == nil {
		t.Fatal("STS redirect was accepted")
	}
	if got := redirected.Load(); got != 0 {
		t.Fatalf("STS client followed %d redirect(s), want zero", got)
	}
}
