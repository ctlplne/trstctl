// SPDX-License-Identifier: BUSL-1.1

package authmethod

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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

// CodeQL #52 (go/request-forgery): the request sent to STS is rebuilt from the
// configured endpoint, the root path and the signed STS parameters alone, each
// in the shape AWS signs. A submitted request carrying any other parameter, a
// repeated one, a malformed value or another path never reaches the network.
func TestHTTPSignedSTSClientSendsOnlyTheConfiguredEndpointAndSignedParameters(t *testing.T) {
	var seen []string
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.RequestURI())
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:role/web</Arn><UserId>AROA:web</UserId><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`))
	}))
	defer sts.Close()
	client := HTTPSignedSTSClient{Endpoint: sts.URL + "/", HTTPClient: sts.Client()}
	signed := "Action=GetCallerIdentity&Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=AKIAEXAMPLEEXAMPLE12%2F20261102%2Fus-east-1%2Fsts%2Faws4_request&X-Amz-Date=20261102T080000Z" +
		"&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature=" + strings.Repeat("ab", 32)
	request := func(rawURL string) error {
		credential := []byte(fmt.Sprintf(`{"method":"GET","url":%q}`, rawURL)) // #nosec G101 -- fabricated signed-request fixture (CWE-798)
		_, err := client.GetCallerIdentity(context.Background(), credential)
		return err
	}
	for name, rawURL := range map[string]string{
		"an extra parameter":    sts.URL + "/?" + signed + "&next=http://metadata.internal/",
		"a repeated parameter":  sts.URL + "/?" + signed + "&Action=GetCallerIdentity",
		"another path":          sts.URL + "/latest/meta-data/?" + signed,
		"a malformed signature": sts.URL + "/?" + strings.Replace(signed, strings.Repeat("ab", 32), "zz", 1),
	} {
		if err := request(rawURL); err == nil {
			t.Fatalf("%s was sent", name)
		}
	}
	if len(seen) != 0 {
		t.Fatalf("refused requests reached STS: %v", seen)
	}
	if err := request(sts.URL + "/?" + signed); err != nil {
		t.Fatalf("a well-formed signed request: %v", err)
	}
	if len(seen) != 1 || !strings.HasPrefix(seen[0], "/?") || strings.Contains(seen[0], "next=") {
		t.Fatalf("STS saw %v", seen)
	}
	for _, name := range []string{"Action=GetCallerIdentity", "Version=2011-06-15", "X-Amz-Signature=" + strings.Repeat("ab", 32)} {
		if !strings.Contains(seen[0], name) {
			t.Fatalf("STS request %q lost %s", seen[0], name)
		}
	}
}
