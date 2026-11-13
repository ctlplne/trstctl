// SPDX-License-Identifier: BUSL-1.1

package hudu_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/docsys"
	"trstctl.com/trstctl/internal/docsys/docsystest"
	"trstctl.com/trstctl/internal/docsys/hudu"
)

const huduKey = "hudu-trstctl-api-key" // #nosec G101 -- a test-only value (CWE-798)

func newClient(t *testing.T, s *docsystest.Hudu, key string) *hudu.Client {
	t.Helper()
	c, err := hudu.New(hudu.Config{BaseURL: s.URL(), AssetLayoutID: 7,
		Fields: hudu.Fields{Inventory: "certificates", NextExpiry: "next_expiry", Count: "certificate_count", Link: "trstctl_link"}},
		http.DefaultClient, hudu.Credentials{APIKey: []byte(key)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// MSP-15 (connector): a record is created as an asset of the configured
// layout under the company with every configured field, found again by its
// name under that company only, and replaced in place; a deleted record
// answers gone; a wrong key is refused before anything is written and never
// named in the error.
func TestHuduRecordsCreateFindUpdateMSP15(t *testing.T) {
	ctx := context.Background()
	s := docsystest.NewHudu(huduKey)
	t.Cleanup(s.Close)
	s.AddCompany(31)
	s.AddCompany(32)
	s.AddLayout(7, "certificates", "next_expiry", "certificate_count", "trstctl_link")
	c := newClient(t, s, huduKey)
	expires := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	content := docsys.Render("Alpha", []docsys.Certificate{{Subject: "CN=www.alpha.example", NotAfter: &expires, Location: "web01:443"}}, 1,
		"https://trstctl.msp.example")

	if _, found, err := c.Find(ctx, "31", content.Title); err != nil || found {
		t.Fatalf("find before create = %v %v", found, err)
	}
	id, err := c.Create(ctx, "31", content)
	if err != nil || id == "" {
		t.Fatalf("create = %q %v", id, err)
	}
	if found, ok, err := c.Find(ctx, "31", content.Title); err != nil || !ok || found != id {
		t.Fatalf("find = %q %v %v, want %q", found, ok, err, id)
	}
	if _, found, err := c.Find(ctx, "32", content.Title); err != nil || found {
		t.Fatalf("company 32 found A's record: %v %v", found, err)
	}
	assets := s.Assets()
	if len(assets) != 1 || assets[0].CompanyID != 31 || assets[0].LayoutID != 7 || assets[0].Name != "trstctl certificates" ||
		assets[0].Fields["next_expiry"] != "2026-12-01" || assets[0].Fields["certificate_count"] != float64(1) ||
		assets[0].Fields["trstctl_link"] != "https://trstctl.msp.example/certificates" || !strings.Contains(assets[0].Fields["certificates"].(string), "web01:443") {
		t.Fatalf("assets = %+v", assets)
	}
	if err := c.Update(ctx, "31", id, docsys.Render("Alpha", nil, 0, "https://trstctl.msp.example")); err != nil {
		t.Fatal(err)
	}
	if assets := s.Assets(); len(assets) != 1 || assets[0].Fields["certificate_count"] != float64(0) || assets[0].Fields["next_expiry"] != "" {
		t.Fatalf("after update = %+v", assets)
	}
	if err := c.Update(ctx, "32", id, content); !errors.Is(err, docsys.ErrRecordGone) {
		t.Fatalf("updating A's asset under company 32 = %v, want gone", err)
	}
	s.DeleteAsset(assets[0].ID)
	if err := c.Update(ctx, "31", id, content); !errors.Is(err, docsys.ErrRecordGone) {
		t.Fatalf("updating a deleted record = %v", err)
	}
	if _, err := c.Create(ctx, "company-a", content); !errors.Is(err, docsys.ErrBeforeWrite) {
		t.Fatalf("a company that is not a number = %v", err)
	}
	wrong := newClient(t, s, "not-the-key")
	if _, err := wrong.Create(ctx, "31", content); !errors.Is(err, docsys.ErrBeforeWrite) || strings.Contains(err.Error(), huduKey) {
		t.Fatalf("a wrong key = %v", err)
	}
	if _, writes, _ := s.Counts(); writes != 2 {
		t.Fatalf("writes = %d, want the create and the update", writes)
	}
}
