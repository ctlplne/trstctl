// SPDX-License-Identifier: BUSL-1.1

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/api"
)

func TestEditionsPackagingListsPQCInFreeCore(t *testing.T) {
	var got struct {
		Packaging struct {
			Editions []struct {
				ID       string   `json:"id"`
				Included []string `json:"included"`
			} `json:"editions"`
		} `json:"packaging"`
	}
	res := httptest.NewRecorder()
	api.New(nil, nil, nil).ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/v1/editions", nil))
	if res.Code != http.StatusOK {
		t.Fatalf("editions = %d %s", res.Code, res.Body.String())
	}
	if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	coreIncludesPQC := false
	for _, edition := range got.Packaging.Editions {
		for _, feature := range edition.Included {
			if feature != "PQC" {
				continue
			}
			if edition.ID != "community" {
				t.Fatalf("PQC listed as an edition-specific feature of %q; it ships in Free Core", edition.ID)
			}
			coreIncludesPQC = true
		}
	}
	if !coreIncludesPQC {
		t.Fatal("Free Core packaging omits PQC")
	}
}
