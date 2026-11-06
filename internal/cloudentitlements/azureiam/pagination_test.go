// SPDX-License-Identifier: BUSL-1.1
package azureiam

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"trstctl.com/trstctl/internal/cloudentitlements/bearerhttp"
)

func TestAzurePaginatedReadStaysBoundAndDiscardsPartialA264(t *testing.T) {
	var mode, calls atomic.Int32
	var nativeOrigin atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch mode.Load() {
		case 0:
			if r.URL.Query().Get("$skiptoken") == "" {
				_, _ = fmt.Fprintf(w, `{"value":[{"id":"one"}],"@odata.nextLink":%q}`, nativeOrigin.Load().(string)+"/v1.0/items?%24select=id&%24skiptoken=next")
			} else {
				_, _ = w.Write([]byte(`{"value":[{"id":"two"}]}`))
			}
		case 1:
			_, _ = w.Write([]byte(`{"value":[{"id":"one"}],"@odata.nextLink":"https://foreign.invalid/v1.0/items?%24select=id"}`))
		case 2:
			_, _ = fmt.Fprintf(w, `{"value":[{"id":"one"}],"@odata.nextLink":%q}`, nativeOrigin.Load().(string)+"/v1.0/items?%24select=id&%24skiptoken=repeated")
		}
	}))
	defer server.Close()
	origin := server.URL
	nativeOrigin.Store(origin)
	client, err := bearerhttp.New(bearerhttp.Config{Endpoint: origin, AllowInsecureLoopback: true, UseToken: func(_ context.Context, use func([]byte) error) error { return use([]byte("owned-reader")) }})
	if err != nil {
		t.Fatal(err)
	}
	type item struct {
		ID string `json:"id"`
	}
	c := collector{}
	values, err := list[item](t.Context(), &c, client, origin, "/v1.0/items?%24select=id", 10)
	if err != nil || len(values) != 2 || values[1].ID != "two" || calls.Load() != 2 {
		t.Fatal("valid native pagination failed", err)
	}
	mode.Store(1)
	calls.Store(0)
	values, err = list[item](t.Context(), &c, client, origin, "/v1.0/items?%24select=id", 10)
	if err == nil || len(values) != 0 || calls.Load() != 1 {
		t.Fatal("foreign cursor followed or partial list presented as complete")
	}
	mode.Store(2)
	calls.Store(0)
	values, err = list[item](t.Context(), &c, client, origin, "/v1.0/items?%24select=id", 10)
	if err == nil || len(values) != 0 || calls.Load() != 2 {
		t.Fatal("repeated cursor admitted")
	}
}
