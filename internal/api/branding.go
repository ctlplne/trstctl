// SPDX-License-Identifier: MPL-2.0

package api

import (
	"net/http"

	"trstctl.com/trstctl/internal/branding"
)

// The served brand (AUD-14, L3).
//
// branding.SetSource was called by the licensed white-label install and
// branding.Resolve — the only consumer of what it sets — was never called
// anywhere in production. A licensed provider saw "Provider white-label
// branding attached" in the log and no downstream customer ever saw their
// brand: the resolver was constructed, wired to a source, and asked nothing.
//
// This is that consumer. It is unauthenticated ON PURPOSE: the brand decides
// what the LOGIN page looks like, so a surface that required a session could
// never brand the one screen a customer sees before they have one.
//
// That constrains what may appear here. The response carries presentation only
// — product name, logo, login message, email strings — and never anything about
// the tenant beyond how to render it. Resolving by Host is a lookup an
// unauthenticated caller can already perform by visiting the host.

// brandPublicRationale is the authz manifest's required justification. It lives
// beside the handler rather than in the route table so the claim and the code it
// describes cannot drift apart.
// The other two public-route rationales live here for the same reason: each is
// a claim about what a surface does NOT expose, and a claim kept far from the
// handler it describes is one that drifts.
const specPublicRationale = "public static API contract: the document contains no tenant data " +
	"or credential material."

const editionsPublicRationale = "public edition posture: the response contains only global " +
	"license state, feature-table rows, and crypto posture; it carries no tenant data or " +
	"credential material."

const brandPublicRationale = "public presentation only: the brand decides what the LOGIN page " +
	"looks like, so a surface requiring a session could never brand the one screen a customer " +
	"sees before they have one. The response carries product name, logo, login message and email " +
	"strings — no tenant data, no credential material, and nothing about the tenant beyond how " +
	"to render it. Resolving by Host is a lookup an unauthenticated caller can already perform " +
	"by visiting that host."

type brandResponse struct {
	ProductName  string            `json:"product_name"`
	LogoDataURI  string            `json:"logo_data_uri,omitempty"`
	LoginMessage string            `json:"login_message,omitempty"`
	Tokens       map[string]string `json:"token_overrides,omitempty"`
	// Custom reports whether a provider brand was actually resolved, so the
	// console can tell "the default, because nothing is configured" from "the
	// default, because this host has no brand". Both render identically and
	// only one is a misconfiguration.
	Custom bool `json:"custom"`
}

func (a *API) getBrand(w http.ResponseWriter, r *http.Request) {
	b := branding.Resolve(r.Context(), r.Host, "")
	def := branding.Default()
	a.writeJSON(w, http.StatusOK, brandResponse{
		ProductName:  b.ProductName,
		LogoDataURI:  b.LogoDataURI,
		LoginMessage: b.LoginMessage,
		Tokens:       b.TokenOverrides,
		Custom:       b.ProductName != def.ProductName || b.LogoDataURI != "" || b.LoginMessage != "",
	})
}
