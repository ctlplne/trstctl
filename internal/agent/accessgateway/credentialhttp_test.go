// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCredentialHTTPDeadlineAlsoBoundsTLSHandshake(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	go func() { _, _ = io.Copy(io.Discard, server) }()
	request := httptest.NewRequest(http.MethodPost, "https://owned.example/token", nil)
	started := time.Now()
	response, err := credentialHTTPRoundTrip(ctx, request, nil, httpUpstream{URL: "https://owned.example/token"}, started.Add(50*time.Millisecond), func(context.Context, string, string) (net.Conn, error) { return client, nil }, nil)
	if response != nil {
		_ = response.Body.Close()
	}
	if err == nil {
		t.Fatal("unresponsive TLS target completed a request")
	}
	if time.Since(started) > 750*time.Millisecond {
		t.Fatal("credential deadline began after the TLS handshake instead of bounding it")
	}
}
