// SPDX-License-Identifier: BUSL-1.1

package awsiamkeys

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// iamDouble answers the three read-only IAM Query calls the reader makes, in
// IAM's XML shapes, with ListUsers split across two pages.
type iamDouble struct {
	mu      sync.Mutex
	actions []string
	auth    []string
}

func (d *iamDouble) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(raw))
	d.mu.Lock()
	d.actions = append(d.actions, form.Get("Action"))
	d.auth = append(d.auth, r.Header.Get("Authorization"))
	d.mu.Unlock()
	if form.Get("Version") != "2010-05-08" {
		http.Error(w, "version", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	switch form.Get("Action") {
	case "ListUsers":
		if form.Get("Marker") == "" {
			_, _ = io.WriteString(w, `<ListUsersResponse><ListUsersResult><Users><member><UserName>deploy-bot</UserName><Arn>arn:aws:iam::123456789012:user/deploy-bot</Arn></member></Users><IsTruncated>true</IsTruncated><Marker>page-2</Marker></ListUsersResult></ListUsersResponse>`)
			return
		}
		_, _ = io.WriteString(w, `<ListUsersResponse><ListUsersResult><Users><member><UserName>backup-job</UserName><Arn>arn:aws:iam::123456789012:user/backup-job</Arn></member></Users><IsTruncated>false</IsTruncated></ListUsersResult></ListUsersResponse>`)
	case "ListAccessKeys":
		switch form.Get("UserName") {
		case "backup-job":
			_, _ = io.WriteString(w, `<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata>`+
				`<member><UserName>backup-job</UserName><AccessKeyId>AKIABACKUPOLD0000001</AccessKeyId><Status>Active</Status><CreateDate>2026-01-02T03:04:05Z</CreateDate></member>`+
				`<member><UserName>backup-job</UserName><AccessKeyId>AKIABACKUPOFF0000002</AccessKeyId><Status>Inactive</Status><CreateDate>2025-06-01T00:00:00Z</CreateDate></member>`+
				`</AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>`)
		case "deploy-bot":
			_, _ = io.WriteString(w, `<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata>`+
				`<member><UserName>deploy-bot</UserName><AccessKeyId>AKIADEPLOYNEW0000003</AccessKeyId><Status>Active</Status><CreateDate>2026-10-01T00:00:00Z</CreateDate></member>`+
				`</AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>`)
		default:
			http.Error(w, "no such user", http.StatusNotFound)
		}
	case "GetAccessKeyLastUsed":
		switch form.Get("AccessKeyId") {
		case "AKIADEPLOYNEW0000003":
			_, _ = io.WriteString(w, `<GetAccessKeyLastUsedResponse><GetAccessKeyLastUsedResult><UserName>deploy-bot</UserName><AccessKeyLastUsed><LastUsedDate>2026-11-01T08:00:00Z</LastUsedDate><ServiceName>s3</ServiceName><Region>us-east-1</Region></AccessKeyLastUsed></GetAccessKeyLastUsedResult></GetAccessKeyLastUsedResponse>`)
		case "AKIABACKUPOLD0000001":
			_, _ = io.WriteString(w, `<GetAccessKeyLastUsedResponse><GetAccessKeyLastUsedResult><UserName>backup-job</UserName><AccessKeyLastUsed><LastUsedDate>2026-02-01T00:00:00Z</LastUsedDate><ServiceName>sts</ServiceName><Region>eu-west-1</Region></AccessKeyLastUsed></GetAccessKeyLastUsedResult></GetAccessKeyLastUsedResponse>`)
		default:
			// A key never used: IAM answers N/A for the service and region and no date.
			_, _ = io.WriteString(w, `<GetAccessKeyLastUsedResponse><GetAccessKeyLastUsedResult><UserName>backup-job</UserName><AccessKeyLastUsed><ServiceName>N/A</ServiceName><Region>N/A</Region></AccessKeyLastUsed></GetAccessKeyLastUsedResult></GetAccessKeyLastUsedResponse>`)
		}
	default:
		http.Error(w, "unexpected action", http.StatusBadRequest)
	}
}

// M3: every user's keys come back with their age and last use, across ListUsers
// pages, and an active key unused for 90 days is the one flagged stale; an
// inactive key is never flagged, a key used two days ago is not, and the
// requests are signed without the secret ever travelling.
func TestKeysReadsAgeAndLastUseAndFlagsNinetyDaysUnusedM3(t *testing.T) {
	double := &iamDouble{}
	srv := httptest.NewServer(double)
	t.Cleanup(srv.Close)
	const secret = "m3-unit-secret-access-key" // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	r, err := New(Config{Endpoint: srv.URL, AccessKeyID: "AKIAM3READER", SecretAccessKey: secret, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := r.Keys(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 {
		t.Fatalf("keys = %+v", keys)
	}
	byID := map[string]Key{}
	for _, k := range keys {
		byID[k.AccessKeyID] = k
	}
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	old, off, fresh := byID["AKIABACKUPOLD0000001"], byID["AKIABACKUPOFF0000002"], byID["AKIADEPLOYNEW0000003"]
	if old.User != "backup-job" || old.LastUsed == nil || !old.LastUsed.Equal(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)) ||
		old.LastUsedService != "sts" || old.LastUsedRegion != "eu-west-1" || !old.Created.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("old key = %+v", old)
	}
	if !old.Stale(now) || old.Unused(now) < StaleAfter {
		t.Fatalf("an active key last used 2026-02-01 is not flagged at %s: unused %s", now, old.Unused(now))
	}
	if off.LastUsed != nil || off.LastUsedService != "" || off.LastUsedRegion != "" || off.Stale(now) {
		t.Fatalf("an inactive, never-used key = %+v stale=%v", off, off.Stale(now))
	}
	if fresh.User != "deploy-bot" || fresh.Stale(now) || fresh.LastUsedService != "s3" {
		t.Fatalf("a key used two days ago = %+v stale=%v", fresh, fresh.Stale(now))
	}
	// M3-L3: each key names its user's ARN as ListUsers reported it.
	if old.UserARN != "arn:aws:iam::123456789012:user/backup-job" || fresh.UserARN != "arn:aws:iam::123456789012:user/deploy-bot" {
		t.Fatalf("user ARNs = %q, %q", old.UserARN, fresh.UserARN)
	}
	// Exactly 90 days unused is the threshold; a day short of it is not.
	if !old.Stale(old.LastUsed.Add(StaleAfter)) || old.Stale(old.LastUsed.Add(StaleAfter-24*time.Hour)) {
		t.Fatal("the stale threshold is not 90 days of non-use")
	}
	// A never-used active key ages from its creation date.
	never := Key{Status: "Active", Created: now.Add(-91 * 24 * time.Hour)}
	if !never.Stale(now) {
		t.Fatal("an active key never used for 91 days is not flagged")
	}
	double.mu.Lock()
	defer double.mu.Unlock()
	if strings.Join(double.actions, ",") != "ListUsers,ListUsers,ListAccessKeys,GetAccessKeyLastUsed,GetAccessKeyLastUsed,ListAccessKeys,GetAccessKeyLastUsed" {
		t.Fatalf("calls = %v (users are read in name order after paging)", double.actions)
	}
	for _, a := range double.auth {
		if !strings.HasPrefix(a, "AWS4-HMAC-SHA256 Credential=AKIAM3READER/") || !strings.Contains(a, "/us-east-1/iam/aws4_request") || strings.Contains(a, secret) {
			t.Fatalf("authorization header = %q", a)
		}
	}
}

// An IAM refusal surfaces as an error naming the call, never the response body.
func TestKeysRefusalNamesTheCallNotTheBodyM3(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "<Error><Code>AccessDenied</Code><Message>user arn:aws:iam::123456789012:user/x</Message></Error>", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	r, err := New(Config{Endpoint: srv.URL, AccessKeyID: "AKIAM3READER", SecretAccessKey: "s", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Keys(t.Context())
	if err == nil || !strings.Contains(err.Error(), "ListUsers: status 403") || strings.Contains(err.Error(), "arn:aws") {
		t.Fatalf("err = %v", err)
	}
	if _, err := New(Config{Endpoint: srv.URL}); err == nil {
		t.Fatal("a reader without credentials was built")
	}
}
