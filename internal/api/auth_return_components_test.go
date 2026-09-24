// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
)

func TestLoginReturnConstructionPreservesLocalComponents(t *testing.T) {
	for _, input := range []string{
		"/certificates?owner=a%20b&expiry=30d#inventory",
		"/certificates?owner=a+b&owner=c%2Bd&flag&empty=&filter=x%26y%3Dz#x/y?z",
		"/assets/a%2fb/%25/é?name=%C3%A9&value=%2f%3f#é%2Fsection",
		"/certificates?",
		"/inventory//item?&flag&&",
	} {
		rec := httptest.NewRecorder()
		if !redirectLoginReturn(rec, httptest.NewRequest(http.MethodGet, "/login", nil), input) {
			t.Fatal("valid local destination rejected")
		}
		got := rec.Header().Get("Location")
		before, err := url.Parse(input)
		if err != nil {
			t.Fatal(err)
		}
		// net/http already cleans duplicate path slashes. Compare that existing
		// behavior while independently requiring original query/fragment values.
		baseline := httptest.NewRecorder()
		http.Redirect(baseline, httptest.NewRequest(http.MethodGet, "/login", nil), before.String(), http.StatusFound)
		expected, err := url.Parse(baseline.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		after, err := url.Parse(got)
		if err != nil || got == "" || after.IsAbs() || after.Host != "" || after.Opaque != "" {
			t.Fatalf("construction must produce a local destination: %q", input)
		}
		if expected.Path != after.Path || before.Fragment != after.Fragment || before.ForceQuery != after.ForceQuery || !reflect.DeepEqual(before.Query(), after.Query()) {
			t.Fatalf("construction changed decoded path, query or fragment: %q -> %q", input, got)
		}
		if safeLoginReturnPath(got) != got {
			t.Fatalf("short canonical destination is not stable: %q", got)
		}
	}
}

func TestLoginReturnConstructionRejectsUnsafeDestinations(t *testing.T) {
	for _, input := range []string{
		"https://outside.example/", "//outside.example/", "/%2foutside.example/",
		"/\\outside.example/", "/%5coutside.example/", "/%61uth/login",
		"/x/../auth/login", "/login", "/?next=%0d%0aLocation:outside",
		"/%00", "/?bad=%", "/#%0a", "", "certificates",
	} {
		if got := safeLoginReturnPath(input); got != "" {
			t.Fatalf("unsafe destination accepted: %q", input)
		}
		rec := httptest.NewRecorder()
		if redirectLoginReturn(rec, httptest.NewRequest(http.MethodGet, "/login", nil), input) || rec.Header().Get("Location") != "" {
			t.Fatalf("unsafe destination reached redirect sink: %q", input)
		}
	}
}
