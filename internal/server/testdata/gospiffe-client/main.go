// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type result struct {
	ID                string `json:"id"`
	CertDER           string `json:"cert_der"`
	HasPrivateKey     bool   `json:"has_private_key"`
	BundleAuthorities int    `json:"bundle_authorities"`
	JWTToken          string `json:"jwt_token,omitempty"`
	ValidatedID       string `json:"validated_id,omitempty"`
	JWTAuthorities    int    `json:"jwt_authorities,omitempty"`
	Audience          string `json:"audience,omitempty"`
}

func main() {
	if len(os.Args) != 2 && len(os.Args) != 3 {
		fail("usage: gospiffe-client <unix://socket> [jwt]")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if len(os.Args) == 3 && os.Args[2] == "jwt" {
		runJWT(ctx, os.Args[1])
		return
	}

	x509ctx, err := workloadapi.FetchX509Context(ctx, workloadapi.WithAddr(os.Args[1]))
	if err != nil {
		fail("FetchX509Context: %v", err)
	}
	svid := x509ctx.DefaultSVID()
	if svid == nil {
		fail("no default X.509-SVID")
	}
	if len(svid.Certificates) == 0 {
		fail("SVID has no certificate chain")
	}
	td, err := spiffeid.TrustDomainFromString("served.test")
	if err != nil {
		fail("trust domain: %v", err)
	}
	authorities := 0
	if bundle, ok := x509ctx.Bundles.Get(td); ok {
		authorities = len(bundle.X509Authorities())
	}
	out := result{
		ID:                svid.ID.String(),
		CertDER:           base64.StdEncoding.EncodeToString(svid.Certificates[0].Raw),
		HasPrivateKey:     svid.PrivateKey != nil,
		BundleAuthorities: authorities,
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fail("encode: %v", err)
	}
}

func runJWT(ctx context.Context, endpoint string) {
	const audience = "trstctl-served-jwt"
	svid, err := workloadapi.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience}, workloadapi.WithAddr(endpoint))
	if err != nil {
		fail("FetchJWTSVID: %v", err)
	}
	token := svid.Marshal()
	if token == "" {
		fail("JWT-SVID has no token")
	}
	validated, err := workloadapi.ValidateJWTSVID(ctx, token, audience, workloadapi.WithAddr(endpoint))
	if err != nil {
		fail("ValidateJWTSVID: %v", err)
	}
	bundles, err := workloadapi.FetchJWTBundles(ctx, workloadapi.WithAddr(endpoint))
	if err != nil {
		fail("FetchJWTBundles: %v", err)
	}
	td, err := spiffeid.TrustDomainFromString("served.test")
	if err != nil {
		fail("trust domain: %v", err)
	}
	authorities := 0
	if bundle, err := bundles.GetJWTBundleForTrustDomain(td); err == nil {
		authorities = len(bundle.JWTAuthorities())
	}
	out := result{
		ID:             svid.ID.String(),
		JWTToken:       token,
		ValidatedID:    validated.ID.String(),
		JWTAuthorities: authorities,
		Audience:       audience,
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fail("encode: %v", err)
	}
}

func fail(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
