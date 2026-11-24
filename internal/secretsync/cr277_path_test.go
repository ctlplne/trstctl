// SPDX-License-Identifier: BUSL-1.1

package secretsync

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestCR277HostedPathTargetsRefuseEscapeBeforeHTTP(t *testing.T) {
	for _, tc := range []struct{ typ, binding string }{
		{"rundeck", "folder keys/project"},
		{"ovh-secret-manager", "okms aaaaaaaa-1111-4222-8333-444444444444"},
	} {
		t.Run(tc.typ, func(t *testing.T) {
			calls := 0
			client := responseDoerFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			})
			p, err := NewHostedSyncPusher(HostedSyncConfig{Type: tc.typ, Binding: tc.binding, Endpoint: "https://example.test", Token: []byte("fake-cr277-token"), HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if err := p.Push(context.Background(), "../outside", []byte("fake-value")); err == nil {
				t.Error("push accepted a parent segment")
			}
			if err := p.Delete(context.Background(), "../outside"); err == nil {
				t.Error("delete accepted a parent segment")
			}
			if _, _, err := p.ReadDigest(context.Background(), "../outside"); err == nil {
				t.Error("read accepted a parent segment")
			}
			if calls != 0 {
				t.Errorf("unsafe path made %d HTTP request(s)", calls)
			}
		})
	}
}

func TestCR277RundeckListWillNotFollowDotDirectory(t *testing.T) {
	calls := 0
	client := responseDoerFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"resources":[{"name":"..","type":"directory"}]}`)), Header: make(http.Header)}, nil
	})
	p, err := NewHostedSyncPusher(HostedSyncConfig{Type: "rundeck", Binding: "folder keys/project", Endpoint: "https://example.test", Token: []byte("fake-cr277-token"), HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.ListKeys(context.Background(), "", 10); err == nil {
		t.Fatal("Rundeck followed an unsafe directory returned by the server")
	}
	if calls != 1 {
		t.Fatalf("Rundeck made %d calls; want only the initial safe directory read", calls)
	}
}

func TestCR277RundeckOrdinaryKeyStillWrites(t *testing.T) {
	var paths []string
	client := responseDoerFunc(func(req *http.Request) (*http.Response, error) {
		paths = append(paths, req.URL.Path)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	})
	p, err := NewHostedSyncPusher(HostedSyncConfig{Type: "rundeck", Binding: "folder keys/project/payments", Endpoint: "https://example.test", Token: []byte("fake-cr277-token"), HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.Push(context.Background(), "inv241/db_password", []byte("fake-value")); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "/api/41/storage/keys/project/payments/inv241/db_password" {
		t.Fatalf("Rundeck ordinary path = %v", paths)
	}
}
