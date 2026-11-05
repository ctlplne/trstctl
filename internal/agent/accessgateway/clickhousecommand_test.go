// SPDX-License-Identifier: BUSL-1.1
package accessgateway

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/crypto/secret"
)

func TestClickHouseRuleSQLCombinesPartsAndExcludesAuthentication(t *testing.T) {
	request := &http.Request{Method: http.MethodPost, URL: &url.URL{Path: "/", RawQuery: "query=TRUNCATE&database=lab&user=client&password=a262-auth-canary"}, Header: http.Header{"Authorization": []string{"a262-auth-canary"}, "X-Clickhouse-Key": []string{"a262-auth-canary"}}}
	sql, phase, parent := clickhouseRuleSQL(request, []byte("TABLE notes"))
	defer secret.Wipe(sql)
	if phase != "query" || string(sql) != "TRUNCATE\nTABLE notes" || !accessrules.ValidDigest(parent) {
		t.Fatal("split query lost its complete SQL")
	}
	clone := request.Clone(request.Context())
	clone.URL.RawQuery = "query=TRUNCATE&database=lab&user=other&password=different"
	clone.Header.Set("Authorization", "different")
	same, phase, sameParent := clickhouseRuleSQL(clone, []byte("TABLE notes"))
	defer secret.Wipe(same)
	if phase != "query" || !bytes.Equal(sql, same) || sameParent != parent {
		t.Fatal("authentication entered rule binding")
	}
	for _, change := range []func(*http.Request){func(r *http.Request) { r.URL.RawQuery += "&query=DROP+TABLE+notes" }, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, func(r *http.Request) { r.Header["Content-Encoding"] = []string{"identity", "gzip"} }, func(r *http.Request) { r.URL.RawQuery += "&decompress=1" }, func(r *http.Request) { r.Header.Set("Content-Type", "multipart/form-data; boundary=owned") }, func(r *http.Request) { r.Method = "CONNECT" }} {
		bad := request.Clone(request.Context())
		change(bad)
		raw, phase, _ := clickhouseRuleSQL(bad, []byte("TABLE notes"))
		secret.Wipe(raw)
		if phase == "query" {
			t.Fatal("ambiguous or encoded SQL reached classifier")
		}
	}
}

type clickhouseRejectBodyReader struct{ reads int }

func (r *clickhouseRejectBodyReader) Read([]byte) (int, error) {
	r.reads++
	return 0, errors.New("unexpected rejected-body read")
}

func TestClickHouseRuleRequestRejectsOversizeWithoutDraining(t *testing.T) {
	tail := &clickhouseRejectBodyReader{}
	raw := io.MultiReader(strings.NewReader("POST / HTTP/1.1\r\nHost: gateway\r\nContent-Length: 2097152\r\n\r\n"), tail)
	limited := &io.LimitedReader{R: raw, N: clickhouseRuleHeaderBytes}
	reader := bufio.NewReader(limited)
	reserved := 0
	_, err := readClickHouseRuleRequest(reader, limited, func(n int) (func(), bool) { reserved += n; return func() { reserved -= n }, true })
	if err == nil || tail.reads != 0 || reserved != 0 {
		t.Fatal("oversized request drained input or leaked reservation")
	}
}

func TestClickHouseRuleRequestPreservesPipelinedBodiesAndWipes(t *testing.T) {
	raw := "POST / HTTP/1.1\r\nHost: gateway\r\nContent-Length: 8\r\n\r\nSELECT 1GET /?query=SELECT+2 HTTP/1.1\r\nHost: gateway\r\n\r\n"
	limited := &io.LimitedReader{R: strings.NewReader(raw), N: clickhouseRuleHeaderBytes}
	reader := bufio.NewReader(limited)
	reserved := 0
	reserve := func(n int) (func(), bool) { reserved += n; return func() { reserved -= n }, true }
	first, err := readClickHouseRuleRequest(reader, limited, reserve)
	if err != nil || string(first.body) != "SELECT 1" {
		t.Fatalf("first pipelined request: %v", err)
	}
	held := first.body
	first.done()
	if !bytes.Equal(held, make([]byte, len(held))) {
		t.Fatal("request body was not wiped")
	}
	second, err := readClickHouseRuleRequest(reader, limited, reserve)
	if err != nil || second.request.URL.Query().Get("query") != "SELECT 2" {
		t.Fatalf("second pipelined request: %v", err)
	}
	second.done()
	if reserved != 0 {
		t.Fatal("request reservation leaked")
	}
}

func FuzzClickHouseRuleRequest(f *testing.F) {
	for _, raw := range []string{"POST / HTTP/1.1\r\nHost: gateway\r\nContent-Length: 8\r\n\r\nSELECT 1", "GET /?query=SELECT+1 HTTP/1.1\r\nHost: gateway\r\n\r\n", "POST / HTTP/1.1\r\nHost: gateway\r\nContent-Length: 999999999\r\n\r\n"} {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		before := bytes.Clone(raw)
		reserved := 0
		limited := &io.LimitedReader{R: bytes.NewReader(raw), N: clickhouseRuleHeaderBytes}
		reader := bufio.NewReader(limited)
		frame, err := readClickHouseRuleRequest(reader, limited, func(n int) (func(), bool) { reserved += n; return func() { reserved -= n }, true })
		if !bytes.Equal(before, raw) {
			t.Fatal("parser changed input")
		}
		if err == nil {
			if len(frame.body) > accessrules.MaxStatementBytes {
				t.Fatal("unbounded body")
			}
			sql, _, _ := clickhouseRuleSQL(frame.request, frame.body)
			secret.Wipe(sql)
			frame.done()
		}
		if reserved != 0 {
			t.Fatal("request leaked reservation")
		}
	})
}
