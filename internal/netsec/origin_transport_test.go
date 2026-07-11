// SPDX-License-Identifier: MPL-2.0

package netsec

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type originCountingTransport struct{ calls int }

func (t *originCountingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls++
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    req,
	}, nil
}

func TestOriginBoundTransportBlocksFreshOriginEscapesBeforeNetwork(t *testing.T) {
	underlying := &originCountingTransport{}
	transport, err := BindTransportToOrigin("https://ca.example.test/directory", underlying)
	if err != nil {
		t.Fatal(err)
	}

	sameOrigin, _ := http.NewRequest(http.MethodPost, "https://ca.example.test/acme/new-order", nil)
	response, err := transport.RoundTrip(sameOrigin)
	if err != nil {
		t.Fatalf("same-origin request rejected: %v", err)
	}
	_ = response.Body.Close()
	if underlying.calls != 1 {
		t.Fatalf("same-origin underlying calls = %d, want 1", underlying.calls)
	}

	for _, target := range []string{
		"https://steering.example.test/credential-capture",
		"http://ca.example.test/plaintext-downgrade",
		"https://ca.example.test:8443/different-port",
		"https://injected:credential@ca.example.test/userinfo",
	} {
		request, _ := http.NewRequest(http.MethodPost, target, nil)
		if _, err := transport.RoundTrip(request); !errors.Is(err, ErrSSRFBlocked) {
			t.Fatalf("fresh request to %s error = %v, want ErrSSRFBlocked", target, err)
		}
		if underlying.calls != 1 {
			t.Fatalf("blocked request to %s reached network transport (%d calls)", target, underlying.calls)
		}
	}
}

func TestOriginBoundTransportRejectsInvalidConfiguredOrigin(t *testing.T) {
	for _, endpoint := range []string{"", "/relative", "file:///tmp/ca", "https://user:pass@ca.example.test"} {
		if _, err := BindTransportToOrigin(endpoint, &originCountingTransport{}); !errors.Is(err, ErrSSRFBlocked) {
			t.Fatalf("BindTransportToOrigin(%q) error = %v, want ErrSSRFBlocked", endpoint, err)
		}
	}
}
