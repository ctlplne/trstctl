// SPDX-License-Identifier: MPL-2.0

package secretstore

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

// Secret bytes served without an explicit content type invite the browser to
// sniff them into a renderable type — the CWE-79 shape gosec's G705 flags on
// this handler. Every access-API response must carry nosniff, secret values go
// out as application/octet-stream, and version metadata as JSON/plain text.
// Guard for that fix: drop any of the header writes and this fails.
func TestAPIResponsesDeclareContentTypeAndNosniff(t *testing.T) {
	authz := allowFn(func(_ context.Context, _, _, _, _ string) (bool, string) { return true, "" })
	api := apiFixture(t, &auditsink.Recorder{}, authz)

	req := func(method, path, body, query string) *recorder {
		t.Helper()
		r, _ := http.NewRequest(method, "http://x/secrets/"+path+query, strings.NewReader(body))
		r.Header.Set("X-Tenant", "t1")
		r.Header.Set("X-Principal", "alice")
		rw := newRecorder()
		api.ServeHTTP(rw, r)
		return rw
	}

	if rw := req("PUT", "app/db", "v1", ""); rw.code != http.StatusOK {
		t.Fatalf("put = %d", rw.code)
	} else if got := rw.header.Get("Content-Type"); got != "application/json" {
		t.Errorf("PUT Content-Type = %q, want application/json", got)
	}

	rw := req("GET", "app/db", "", "")
	if rw.code != http.StatusOK {
		t.Fatalf("get = %d", rw.code)
	}
	if got := rw.header.Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("secret GET Content-Type = %q, want application/octet-stream (a sniffable secret is renderable)", got)
	}
	if got := rw.header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("secret GET X-Content-Type-Options = %q, want nosniff", got)
	}

	if rw := req("GET", "app/db", "", "?versions=1"); rw.header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("versions GET Content-Type = %q, want text/plain; charset=utf-8", rw.header.Get("Content-Type"))
	}

	if rw := req("POST", "app/db", "", "?rollback=1"); rw.code != http.StatusOK {
		t.Fatalf("rollback = %d", rw.code)
	} else if got := rw.header.Get("Content-Type"); got != "application/json" {
		t.Errorf("rollback Content-Type = %q, want application/json", got)
	}
}
