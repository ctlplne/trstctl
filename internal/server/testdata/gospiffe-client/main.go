package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

type result struct {
	ID                string `json:"id"`
	CertDER           string `json:"cert_der"`
	HasPrivateKey     bool   `json:"has_private_key"`
	BundleAuthorities int    `json:"bundle_authorities"`
}

func main() {
	if len(os.Args) != 2 {
		fail("usage: gospiffe-client <unix://socket>")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

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

func fail(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
