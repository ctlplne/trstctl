// SPDX-License-Identifier: BUSL-1.1

package accessweb

import (
	"net/url"
	"testing"
)

func TestSignInValidateA273(t *testing.T) {
	good := []SignIn{
		{Mode: SignInForm, LoginPath: "/login", UsernameField: "username", PasswordField: "password"},
		{Mode: SignInForm, LoginPath: "/ui/sign-in", UsernameField: "user[name]", PasswordField: "user[password]", BrowserCookies: []string{"XSRF-TOKEN"}},
		{Mode: SignInHeader, Header: "Authorization", HeaderPrefix: "Bearer "},
		{Mode: SignInHeader, Header: "X-Api-Key"},
		{Mode: SignInBasic},
	}
	for _, s := range good {
		if err := s.Validate(); err != nil {
			t.Fatalf("%+v: %v", s, err)
		}
	}
	bad := map[string]SignIn{
		"no mode":              {},
		"unknown mode":         {Mode: "saml"},
		"form without page":    {Mode: SignInForm, UsernameField: "u", PasswordField: "p"},
		"form page with query": {Mode: SignInForm, LoginPath: "/login?next=/", UsernameField: "u", PasswordField: "p"},
		"form page relative":   {Mode: SignInForm, LoginPath: "login", UsernameField: "u", PasswordField: "p"},
		"form page escapes":    {Mode: SignInForm, LoginPath: "/a/../login", UsernameField: "u", PasswordField: "p"},
		"form page host":       {Mode: SignInForm, LoginPath: "//evil.example/login", UsernameField: "u", PasswordField: "p"},
		"form same fields":     {Mode: SignInForm, LoginPath: "/login", UsernameField: "p", PasswordField: "p"},
		"form field quote":     {Mode: SignInForm, LoginPath: "/login", UsernameField: `u"`, PasswordField: "p"},
		"form with header":     {Mode: SignInForm, LoginPath: "/login", UsernameField: "u", PasswordField: "p", Header: "X-Api-Key"},
		"header cookie":        {Mode: SignInHeader, Header: "Cookie"},
		"header host":          {Mode: SignInHeader, Header: "Host"},
		"header forwarded":     {Mode: SignInHeader, Header: "X-Forwarded-For"},
		"header bad name":      {Mode: SignInHeader, Header: "X Api"},
		"header prefix CRLF":   {Mode: SignInHeader, Header: "Authorization", HeaderPrefix: "Bearer\r\n"},
		"header with form":     {Mode: SignInHeader, Header: "X-Api-Key", LoginPath: "/login"},
		"basic with header":    {Mode: SignInBasic, Header: "X-Api-Key"},
		"cookie twice":         {Mode: SignInBasic, BrowserCookies: []string{"a", "a"}},
		"cookie bad name":      {Mode: SignInBasic, BrowserCookies: []string{"a b"}},
		"too many cookies":     {Mode: SignInBasic, BrowserCookies: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}},
	}
	for name, s := range bad {
		if s.Validate() == nil {
			t.Fatalf("%s: accepted %+v", name, s)
		}
	}
	if !(SignIn{Mode: SignInBasic, BrowserCookies: []string{"XSRF-TOKEN"}}).AllowsBrowserCookie("XSRF-TOKEN") ||
		(SignIn{Mode: SignInBasic}).AllowsBrowserCookie("session") {
		t.Fatal("browser cookie allowance")
	}
}

func TestRouteValidateA273(t *testing.T) {
	ca := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	for _, r := range []Route{
		{URL: "https://grafana.internal.example"},
		{URL: "https://10.0.0.5:8443/", CAPEM: ca, ServerName: "console.internal.example"},
	} {
		if err := r.Validate(false); err != nil {
			t.Fatalf("%+v: %v", r, err)
		}
	}
	if err := (Route{URL: "http://127.0.0.1:8080"}).Validate(true); err != nil {
		t.Fatalf("lab loopback: %v", err)
	}
	for name, r := range map[string]Route{
		"plain http":         {URL: "http://console.internal.example"},
		"loopback, no opt":   {URL: "https://127.0.0.1:8443"},
		"user info":          {URL: (&url.URL{Scheme: "https", User: url.UserPassword("admin", "x"), Host: "console.internal.example"}).String()},
		"path":               {URL: "https://console.internal.example/admin"},
		"query":              {URL: "https://console.internal.example/?a=b"},
		"fragment":           {URL: "https://console.internal.example/#x"},
		"no host":            {URL: "https:///"},
		"other scheme":       {URL: "ftp://console.internal.example"},
		"CA not PEM":         {URL: "https://console.internal.example", CAPEM: "not a certificate"},
		"server name spaces": {URL: "https://console.internal.example", ServerName: "a b"},
	} {
		if r.Validate(false) == nil {
			t.Fatalf("%s: accepted %+v", name, r)
		}
	}
	if (Route{URL: "https://console.internal.example/"}).Origin() != "https://console.internal.example" {
		t.Fatal("origin")
	}
}
