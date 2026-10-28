// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto/ctlog/ctlogtest"
	"trstctl.com/trstctl/internal/store"
)

func pendingCTInclusion(t *testing.T, logURL string, logKey []byte) store.CertificateSCT {
	t.Helper()
	return store.CertificateSCT{
		SubmissionID: "6f1c2a8e-0d4b-5e7a-9c3f-1b2d3e4f5a6b", LogURL: logURL, SCTStatus: store.SCTVerified,
		LeafHash: strings.Repeat("ab", 32), LogPublicKey: logKey, SCTTimestamp: time.Now().UTC(),
		AllowPrivateEndpoint: true, PrivateEgressCIDRs: []string{serviceNowSinkCIDR(t, logURL)},
	}
}

func TestCTInclusionIsNotCheckedForALogWithoutRFC6962TreeHeads(t *testing.T) {
	static := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(static.Close)
	keyed := ctlogtest.NewSigningServer()
	t.Cleanup(keyed.Close)

	result, decided, err := checkCTInclusion(t.Context(), pendingCTInclusion(t, static.URL, keyed.PublicKeyDER()), map[string]ctTreeHead{})
	if err != nil || !decided || result.Status != store.InclusionNotChecked || !strings.Contains(result.Reason, "get-sth") {
		t.Fatalf("a log without get-sth = (%+v, %v, %v); want not_checked with the reason", result, decided, err)
	}
}

func TestCTInclusionFlagsATreeHeadTheLogKeyDoesNotVerify(t *testing.T) {
	logSrv := ctlogtest.NewSigningServer()
	t.Cleanup(logSrv.Close)
	other := ctlogtest.NewSigningServer()
	t.Cleanup(other.Close)

	result, decided, err := checkCTInclusion(t.Context(), pendingCTInclusion(t, logSrv.URL(), other.PublicKeyDER()), map[string]ctTreeHead{})
	if err != nil || !decided || result.Status != store.InclusionProofBad || !strings.Contains(result.Reason, "tree head") {
		t.Fatalf("a tree head signed by another key = (%+v, %v, %v); want proof_invalid", result, decided, err)
	}
}

func TestCTInclusionStaysPendingWhileTheLogCannotBeRead(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(failing.Close)
	keyed := ctlogtest.NewSigningServer()
	t.Cleanup(keyed.Close)

	result, decided, err := checkCTInclusion(t.Context(), pendingCTInclusion(t, failing.URL, keyed.PublicKeyDER()), map[string]ctTreeHead{})
	if err == nil || decided || result.Status != "" {
		t.Fatalf("an unavailable log = (%+v, %v, %v); want an error and no decision", result, decided, err)
	}
}
