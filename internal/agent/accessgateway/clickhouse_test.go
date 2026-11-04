// SPDX-License-Identifier: BUSL-1.1

package accessgateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
)

// chConnRecorder records one connection; frames renders its events.
func chConnRecorder(t *testing.T) (*connRecorder, func() string) {
	t.Helper()
	up := &fakeUploader{}
	rec := newSessionRecorder(context.Background(), up, relay.Job{JobID: 1, Attempt: 1}, time.Now, []byte("s3ss10n-Pa55word"))
	conn := rec.connection()
	return conn, func() string {
		conn.close()
		rec.close()
		var events []string
		lines := bufio.NewScanner(bytes.NewReader(bytes.Join(up.chunks, nil)))
		for lines.Scan() {
			var f frame
			if err := json.Unmarshal(lines.Bytes(), &f); err != nil {
				t.Fatal(err)
			}
			if f.Kind != "" {
				events = append(events, f.Kind+": "+f.Text)
			}
		}
		return strings.Join(events, "\n")
	}
}

func TestClickHouseRelaySignsEveryRequestInAsTheSessionUser(t *testing.T) {
	type seen struct{ user, key, auth, query, body string }
	got := make(chan seen, 4)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- seen{r.Header.Get("X-ClickHouse-User"), r.Header.Get("X-ClickHouse-Key"), r.Header.Get("Authorization"), r.URL.RawQuery, string(body)}
		w.Header().Set("X-ClickHouse-Summary", `{"read_rows":"1"}`)
		_, _ = io.WriteString(w, "1\tghp_"+strings.Repeat("C", 36)+"\n")
	}))
	defer upstream.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	rec, frames := chConnRecorder(t)
	credential := []byte(`{"username":"trstctl_ch_1","password":"s3ss10n-Pa55word","valid_until":"2026-11-04T23:00:00Z"}`)
	served := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			served <- err
			return
		}
		served <- serveClickHouse(context.Background(), conn, credential, httpUpstream{URL: upstream.URL}, nil, rec)
	}()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	}, MaxConnsPerHost: 1}}
	// A client's own credentials, in every form ClickHouse reads them.
	req, _ := http.NewRequest(http.MethodPost, "http://gateway/?user=default&password=hunter2&database=orders", strings.NewReader("SELECT 1, note FROM notes"))
	req.SetBasicAuth("default", "hunter2")
	req.Header.Set("X-ClickHouse-User", "default")
	req.Header.Set("X-ClickHouse-Key", "hunter2")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "ghp_") {
		t.Fatalf("response = %d %q", resp.StatusCode, body)
	}
	s := <-got
	if s.user != "trstctl_ch_1" || s.key != "s3ss10n-Pa55word" || s.auth != "" || s.query != "database=orders" || s.body != "SELECT 1, note FROM notes" {
		t.Fatalf("upstream saw %+v", s)
	}
	// A second request on the same connection is signed in the same way.
	resp, err = client.Get("http://gateway/?query=SELECT%202")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if s := <-got; s.user != "trstctl_ch_1" || s.query != "query=SELECT+2" {
		t.Fatalf("second request upstream saw %+v", s)
	}
	client.CloseIdleConnections()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the relay did not end when the client closed")
	}
	text := frames()
	for _, want := range []string{"request: POST / body=SELECT 1, note FROM notes", "request: GET / query=SELECT 2",
		`response: 200 {"read_rows":"1"}: 1	[masked:github-token]`} {
		if !strings.Contains(text, want) {
			t.Fatalf("recording lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "hunter2") || strings.Contains(text, "Pa55word") {
		t.Fatalf("recording kept a credential:\n%s", text)
	}
}

func TestClickHouseRelayRefusesAnUnusableSession(t *testing.T) {
	for name, tc := range map[string]struct{ credential, upstream string }{
		"no password":  {`{"username":"u"}`, "http://127.0.0.1:1/"},
		"not json":     {`u:p`, "http://127.0.0.1:1/"},
		"bad upstream": {`{"username":"u","password":"p"}`, "ftp://h/"},
	} {
		a, b := net.Pipe()
		err := serveClickHouse(context.Background(), a, []byte(tc.credential), httpUpstream{URL: tc.upstream}, nil, nil)
		_ = a.Close()
		_ = b.Close()
		if err == nil {
			t.Errorf("%s: served", name)
		}
	}
}
