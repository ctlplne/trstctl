// SPDX-License-Identifier: BUSL-1.1

package itglue_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/docsys"
	"trstctl.com/trstctl/internal/docsys/docsystest"
	"trstctl.com/trstctl/internal/docsys/itglue"
)

const itglueKey = "ITG.trstctl-api-key" // #nosec G101 -- a test-only value (CWE-798)

func newClient(t *testing.T, s *docsystest.ITGlue, key string) *itglue.Client {
	t.Helper()
	c, err := itglue.New(itglue.Config{BaseURL: s.URL(), FlexibleAssetTypeID: 33,
		Traits: itglue.Traits{Title: "name", Inventory: "certificates", NextExpiry: "next-expiry", Count: "certificate-count", Link: "trstctl-link"}},
		http.DefaultClient, itglue.Credentials{APIKey: []byte(key)})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// MSP-14 (connector): a record is created as a flexible asset of the
// configured type under the organization with every configured trait, found
// again by its name under that organization only, and replaced in place; a
// deleted record answers gone; a wrong key is refused before anything is
// written and never named in the error.
func TestITGlueRecordsCreateFindUpdateMSP14(t *testing.T) {
	ctx := context.Background()
	s := docsystest.NewITGlue(itglueKey)
	t.Cleanup(s.Close)
	s.AddOrganization(11)
	s.AddOrganization(22)
	s.AddType(33, "name", "certificates", "next-expiry", "certificate-count", "trstctl-link")
	c := newClient(t, s, itglueKey)
	expires := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	content := docsys.Render("Alpha <Corp>", []docsys.Certificate{{Subject: "CN=www.alpha.example", SANs: []string{"www.alpha.example"},
		Issuer: "CN=Issuing CA", Serial: "0a1b", NotAfter: &expires, Location: "web01:443"}}, 1, "https://trstctl.msp.example/")
	if !strings.Contains(content.HTML, "Alpha &lt;Corp&gt;") || !strings.Contains(content.HTML, "2026-12-01") ||
		content.Link != "https://trstctl.msp.example/certificates" || content.Count != 1 || !content.NextExpiry.Equal(expires) {
		t.Fatalf("rendered content = %+v", content)
	}

	if _, found, err := c.Find(ctx, "11", content.Title); err != nil || found {
		t.Fatalf("find before create = %v %v", found, err)
	}
	id, err := c.Create(ctx, "11", content)
	if err != nil || id == "" {
		t.Fatalf("create = %q %v", id, err)
	}
	if found, ok, err := c.Find(ctx, "11", content.Title); err != nil || !ok || found != id {
		t.Fatalf("find = %q %v %v, want %q", found, ok, err, id)
	}
	if _, found, err := c.Find(ctx, "22", content.Title); err != nil || found {
		t.Fatalf("organization 22 found A's record: %v %v", found, err)
	}
	assets := s.Assets()
	if len(assets) != 1 || assets[0].OrgID != 11 || assets[0].TypeID != 33 || assets[0].Traits["name"] != "trstctl certificates" ||
		assets[0].Traits["next-expiry"] != "2026-12-01" || assets[0].Traits["certificate-count"] != float64(1) ||
		assets[0].Traits["trstctl-link"] != "https://trstctl.msp.example/certificates" || !strings.Contains(assets[0].Traits["certificates"].(string), "web01:443") {
		t.Fatalf("assets = %+v", assets)
	}

	updated := docsys.Render("Alpha <Corp>", nil, 0, "https://trstctl.msp.example")
	if err := c.Update(ctx, "11", id, updated); err != nil {
		t.Fatal(err)
	}
	if assets := s.Assets(); len(assets) != 1 || assets[0].Traits["certificate-count"] != float64(0) || assets[0].Traits["next-expiry"] != nil {
		t.Fatalf("after update = %+v", assets)
	}
	s.DeleteAsset(assets[0].ID)
	if err := c.Update(ctx, "11", id, updated); !errors.Is(err, docsys.ErrRecordGone) {
		t.Fatalf("updating a deleted record = %v", err)
	}
	if _, err := c.Create(ctx, "org-a", content); !errors.Is(err, docsys.ErrBeforeWrite) {
		t.Fatalf("an organization that is not a number = %v", err)
	}

	wrong := newClient(t, s, "not-the-key")
	if _, err := wrong.Create(ctx, "11", content); !errors.Is(err, docsys.ErrBeforeWrite) || strings.Contains(err.Error(), itglueKey) {
		t.Fatalf("a wrong key = %v", err)
	}
	if _, writes, _ := s.Counts(); writes != 2 {
		t.Fatalf("writes = %d, want the create and the update", writes)
	}
}
