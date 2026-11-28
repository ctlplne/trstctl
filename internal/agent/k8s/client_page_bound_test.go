// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestClientReportsOversizedAPIResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxAPIBody+1)))
	}))
	defer server.Close()
	client := New(server.URL, "", "", server.Client())
	_, _, err := client.request(context.Background(), http.MethodGet, "/api/v1/example", nil)
	if !errors.Is(err, errAPIBodyTooLarge) {
		t.Fatalf("oversized response error = %v, want size limit", err)
	}
}

func TestListReducesPageSizeUntilSnapshotFits(t *testing.T) {
	var limits []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		limits = append(limits, limit)
		offset, _ := strconv.Atoi(r.URL.Query().Get("continue"))
		end := min(offset+limit, 500)
		page := struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
				Continue        string `json:"continue,omitempty"`
			} `json:"metadata"`
			Items []map[string]any `json:"items"`
		}{}
		page.Metadata.ResourceVersion = "27"
		if end < 500 {
			page.Metadata.Continue = strconv.Itoa(end)
		}
		for n := offset; n < end; n++ {
			page.Items = append(page.Items, map[string]any{
				"metadata": map[string]any{"name": strconv.Itoa(n)},
				"spec":     map[string]any{"padding": strings.Repeat("x", 9<<10)},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer server.Close()
	client := New(server.URL, "", "", server.Client())
	items, rv, err := client.list(context.Background(), "/apis/example/v1/items", "")
	if err != nil {
		t.Fatal(err)
	}
	if rv != "27" || len(items) != 500 {
		t.Fatalf("snapshot = %q, %d items; want version 27 and 500 items", rv, len(items))
	}
	if len(limits) != 3 || limits[0] != 500 || limits[1] != 250 || limits[2] != 250 {
		t.Fatalf("page limits = %v, want [500 250 250]", limits)
	}
}

func TestListRestartsSnapshotAfterLaterPageNeedsSmallerLimit(t *testing.T) {
	type request struct {
		limit, offset int
	}
	var requests []request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("continue"))
		requests = append(requests, request{limit, offset})
		if limit > listPageSize/2 && offset == 2 {
			_, _ = w.Write([]byte(strings.Repeat("x", maxAPIBody+1)))
			return
		}
		end := min(offset+2, 4)
		version := "28"
		if limit > listPageSize/2 {
			version = "27"
		}
		page := struct {
			Metadata struct {
				ResourceVersion string `json:"resourceVersion"`
				Continue        string `json:"continue,omitempty"`
			} `json:"metadata"`
			Items []map[string]any `json:"items"`
		}{}
		page.Metadata.ResourceVersion = version
		if end < 4 {
			page.Metadata.Continue = strconv.Itoa(end)
		}
		for n := offset; n < end; n++ {
			page.Items = append(page.Items, map[string]any{
				"metadata": map[string]any{"name": version + "-" + strconv.Itoa(n)},
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer server.Close()
	client := New(server.URL, "", "", server.Client())
	items, rv, err := client.list(context.Background(), "/apis/example/v1/items", "")
	if err != nil {
		t.Fatal(err)
	}
	if rv != "28" || len(items) != 4 || objectName(items[0]) != "28-0" {
		t.Fatalf("snapshot = %q, items = %v; want four items from version 28", rv, items)
	}
	want := []request{{500, 0}, {500, 2}, {250, 0}, {250, 2}}
	if len(requests) != len(want) {
		t.Fatalf("requests = %v, want %v", requests, want)
	}
	for n, got := range requests {
		if got != want[n] {
			t.Fatalf("requests = %v, want %v", requests, want)
		}
	}
}

func TestListReportsSingleResourceCapacityFailure(t *testing.T) {
	var limits []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		limits = append(limits, limit)
		_, _ = w.Write([]byte(strings.Repeat("x", maxAPIBody+1)))
	}))
	defer server.Close()
	client := New(server.URL, "", "", server.Client())
	_, _, err := client.list(context.Background(), "/apis/example/v1/items", "")
	if !errors.Is(err, errAPIBodyTooLarge) {
		t.Fatalf("single resource capacity error = %v, want response limit", err)
	}
	if len(limits) < 2 || limits[0] != listPageSize || limits[len(limits)-1] != 1 {
		t.Fatalf("page limits = %v, want reduction from %d to 1", limits, listPageSize)
	}
}

func TestControllerPostureReportsInformerFailure(t *testing.T) {
	csrs := newInformer(nil, "/apis/example/v1/items", "", nil)
	csrs.fail(errAPIBodyTooLarge)
	runtime := &controllerRuntime{
		csrs: csrs, requests: newInformer(nil, "", "", nil), bundles: newInformer(nil, "", "", nil),
		issuersSynced: true,
		posture:       map[string]map[string]PostureResource{},
		failing:       map[string]map[string]bool{},
	}
	report := runtime.postureReport()
	if report.CertificateSigning.FailureCode != "reconcile_failed" || report.CertificateSigning.Complete {
		t.Fatalf("capacity failure posture = %+v, want reconcile_failed", report.CertificateSigning)
	}
}
