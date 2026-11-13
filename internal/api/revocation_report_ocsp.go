// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/netsec"
	"trstctl.com/trstctl/internal/store"
)

// A245-L3: the CA facet of a certificate an external CA issued is read back
// from that CA's own OCSP responder, named in the certificate's Authority
// Information Access, with the issuer from the chain kept with it. Only a
// response signed for that issuer, about that serial and not past its next
// update counts: revoked confirms the revocation, good leaves it pending, and
// unknown fails it. A certificate naming no responder, a chain without the
// issuer, or a responder that can't be read stays not observed, saying why.

const (
	// maxExternalOCSPReadbacks bounds the responders one report asks.
	maxExternalOCSPReadbacks = 10
	externalOCSPTimeout      = 5 * time.Second
	externalOCSPMaxResponse  = 64 << 10
)

func (a *API) externalCAStatus(ctx context.Context, cert store.Certificate) revocationFacet {
	notObserved := func(detail string) revocationFacet {
		return revocationFacet{State: revocationNotObserved, Detail: "revoked in trstctl's inventory; " + detail}
	}
	leafDER, issuerDER, urls, err := crypto.LeafOCSPTarget(cert.CertificatePEM)
	switch {
	case err != nil:
		return notObserved("the stored certificate cannot be read for an OCSP request")
	case len(urls) == 0:
		return notObserved("the certificate names no OCSP responder, so the external CA's own status is not read back")
	case issuerDER == nil:
		return notObserved("the issuing CA's certificate is not kept with this certificate, so its OCSP responder cannot be asked")
	}
	responder := ""
	for _, u := range urls {
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			responder = u
			break
		}
	}
	if responder == "" {
		return notObserved("the certificate names no HTTP OCSP responder")
	}
	request, err := crypto.BuildOCSPRequest(leafDER, issuerDER)
	if err != nil {
		return notObserved("an OCSP request cannot be built for this certificate")
	}
	client := a.externalOCSPClient
	if client == nil {
		client = netsec.SafeClient(externalOCSPTimeout)
	}
	askCtx, cancel := context.WithTimeout(ctx, externalOCSPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(askCtx, http.MethodPost, responder, bytes.NewReader(request))
	if err != nil {
		return notObserved("the OCSP responder's URL cannot be used")
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
	resp, err := client.Do(req)
	if err != nil {
		return notObserved("the external CA's OCSP responder could not be reached")
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, externalOCSPMaxResponse+1))
	if err != nil || resp.StatusCode != http.StatusOK || len(body) > externalOCSPMaxResponse {
		return notObserved(fmt.Sprintf("the external CA's OCSP responder answered HTTP %d", resp.StatusCode))
	}
	info, err := crypto.ParseOCSPResponse(body, issuerDER)
	if err != nil {
		return notObserved("the external CA's OCSP answer is not a response its issuer signed")
	}
	if !strings.EqualFold(strings.TrimLeft(info.Serial, "0"), strings.TrimLeft(cert.Serial, "0")) {
		return notObserved("the external CA's OCSP responder answered about another serial")
	}
	now := time.Now()
	if !info.NextUpdate.IsZero() && now.After(info.NextUpdate) {
		return notObserved("the external CA's OCSP answer is past its next update")
	}
	thisUpdate := info.ThisUpdate.UTC()
	switch info.Status {
	case crypto.OCSPRevoked:
		at := info.RevokedAt.UTC()
		return revocationFacet{State: revocationConfirmed, At: &at,
			Detail: fmt.Sprintf("the external CA's OCSP responder answers revoked (as of %s)", thisUpdate.Format(time.RFC3339))}
	case crypto.OCSPGood:
		return revocationFacet{State: revocationPending, At: &thisUpdate,
			Detail: fmt.Sprintf("the external CA's OCSP responder still answers good (as of %s); it has not published the revocation yet", thisUpdate.Format(time.RFC3339))}
	default:
		return revocationFacet{State: revocationFailed, At: &thisUpdate,
			Detail: "the external CA's OCSP responder does not know this serial"}
	}
}
