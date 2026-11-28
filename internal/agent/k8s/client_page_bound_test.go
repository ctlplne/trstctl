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
	snapshot, err := client.list(context.Background(), "/apis/example/v1/items", "")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.resourceVersion != "27" || len(snapshot.items) != 500 {
		t.Fatalf("snapshot = %q, %d items; want version 27 and 500 items", snapshot.resourceVersion, len(snapshot.items))
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
	snapshot, err := client.list(context.Background(), "/apis/example/v1/items", "")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.resourceVersion != "28" || len(snapshot.items) != 4 || objectName(snapshot.items[0]) != "28-0" {
		t.Fatalf("snapshot = %q, items = %v; want four items from version 28", snapshot.resourceVersion, snapshot.items)
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
	_, err := client.list(context.Background(), "/apis/example/v1/items", "")
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

func TestControllerPostureReportsIssuerInformerFailure(t *testing.T) {
	clusterIssuers := newInformer(nil, "/apis/trstctl.com/v1alpha1/clusterissuers", "", nil)
	clusterIssuers.fail(errAPIBodyTooLarge)
	runtime := &controllerRuntime{
		clusterIssuers: clusterIssuers, issuers: newInformer(nil, "", "", nil),
		csrs: newInformer(nil, "", "", nil), requests: newInformer(nil, "", "", nil),
		bundles: newInformer(nil, "", "", nil),
		posture: map[string]map[string]PostureResource{},
		failing: map[string]map[string]bool{},
	}
	report := runtime.postureReport()
	for name, section := range map[string]PostureSection{
		"signing": report.CertificateSigning, "requests": report.CertificateRequests, "bundles": report.TrustBundles,
	} {
		if section.Complete || section.FailureCode != "reconcile_failed" {
			t.Fatalf("%s posture = %+v, want reconcile_failed", name, section)
		}
	}
}

func TestListKeepsOtherResourcesWhenOneNeedsMetadataOnlyRead(t *testing.T) {
	var metadataReads int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("continue"))
		metadata := strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadataList")
		if metadata {
			metadataReads++
		}
		if !metadata && (limit > 1 || offset == 1) {
			_, _ = w.Write([]byte(strings.Repeat("x", maxAPIBody+1)))
			return
		}
		page := struct {
			Kind       string `json:"kind,omitempty"`
			APIVersion string `json:"apiVersion,omitempty"`
			Metadata   struct {
				ResourceVersion string `json:"resourceVersion"`
				Continue        string `json:"continue,omitempty"`
			} `json:"metadata"`
			Items []map[string]any `json:"items"`
		}{}
		page.Metadata.ResourceVersion = "27"
		if offset < 2 {
			page.Metadata.Continue = strconv.Itoa(offset + 1)
		}
		if metadata {
			page.Kind, page.APIVersion = "PartialObjectMetadataList", "meta.k8s.io/v1"
		}
		page.Items = []map[string]any{{
			"metadata": map[string]any{
				"name": "item-" + strconv.Itoa(offset), "namespace": "apps",
				"uid":             "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa" + strconv.Itoa(offset),
				"resourceVersion": strconv.Itoa(offset + 10),
			},
		}}
		if !metadata {
			page.Items[0]["spec"] = map[string]any{"value": "ready"}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer server.Close()
	client := New(server.URL, "", "", server.Client())
	snapshot, err := client.list(context.Background(), "/apis/example/v1/items", "")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.resourceVersion != "27" || len(snapshot.items) != 2 || len(snapshot.omitted) != 1 || metadataReads != 1 {
		t.Fatalf("snapshot = %+v, metadata reads = %d; want two full items and one identified omission", snapshot, metadataReads)
	}
	if objectName(snapshot.omitted[0]) != "item-1" || objectName(snapshot.items[1]) != "item-2" {
		t.Fatalf("snapshot items = %v, omitted = %v", snapshot.items, snapshot.omitted)
	}
	inf := newInformer(client, "/apis/example/v1/items", "", func(string, map[string]any) {})
	if _, err := inf.relist(context.Background()); err != nil {
		t.Fatal(err)
	}
	synced, installed, lastErr := inf.state()
	if !synced || !installed || !errors.Is(lastErr, errAPIBodyTooLarge) || len(inf.keys()) != 2 {
		t.Fatalf("informer state = synced:%v installed:%v error:%v keys:%v", synced, installed, lastErr, inf.keys())
	}
	runtime := &controllerRuntime{
		csrs: inf, requests: newInformer(nil, "", "", nil), bundles: newInformer(nil, "", "", nil),
		issuersSynced: true,
		posture:       map[string]map[string]PostureResource{},
		failing:       map[string]map[string]bool{},
	}
	section := runtime.postureReport().CertificateSigning
	if section.FailureCode != "reconcile_failed" || len(section.Resources) != 1 ||
		section.Resources[0].Name != "item-1" || section.Resources[0].Reason != "api_response_too_large" {
		t.Fatalf("identified resource posture = %+v", section)
	}
	updated, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"name": "item-1", "namespace": "apps", "uid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
			"resourceVersion": "21",
		},
		"spec": map[string]any{"value": "ready"},
	})
	if err != nil {
		t.Fatal(err)
	}
	version := "27"
	if err := inf.apply(watchEvent{Type: "MODIFIED", Object: updated}, &version); err != nil {
		t.Fatal(err)
	}
	_, _, lastErr = inf.state()
	if lastErr != nil || len(inf.keys()) != 3 || !runtime.postureReport().CertificateSigning.Complete {
		t.Fatalf("recovered informer has error %v, keys %v", lastErr, inf.keys())
	}
}

func TestListRequiresMetadataOnlyCapabilityToContinuePastLargeResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Accept"), "PartialObjectMetadataList") {
			w.WriteHeader(http.StatusNotAcceptable)
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("x", maxAPIBody+1)))
	}))
	defer server.Close()
	client := New(server.URL, "", "", server.Client())
	_, err := client.list(context.Background(), "/apis/example/v1/items", "")
	if err == nil || !strings.Contains(err.Error(), "status 406") {
		t.Fatalf("unsupported metadata response error = %v, want explicit refusal", err)
	}
}
