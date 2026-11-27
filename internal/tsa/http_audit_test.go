// SPDX-License-Identifier: BUSL-1.1

package tsa

import (
	"bytes"
	"encoding/asn1"
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
)

func TestPublicTimestampSkipsPerTokenAuditAndInternalTimestampKeepsIt(t *testing.T) {
	a, _ := newTSA(t, nil)
	recorder := &auditsink.Recorder{}
	a.cfg.Audit = recorder
	request, err := asn1.Marshal(asn1TimeStampReq{
		Version: 1,
		MessageImprint: asn1MessageImprint{
			HashAlgorithm: asn1AlgorithmIdentifier{Algorithm: oidSHA256},
			HashedMessage: crypto.SHA256Sum([]byte("public timestamp subject")),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		r := httptest.NewRequest(http.MethodPost, "/tsa", bytes.NewReader(request))
		r.Header.Set("Content-Type", ContentTypeQuery)
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("public timestamp status = %d, want 200", w.Code)
		}
	}
	if got := recorder.Count("tsa.timestamp.issued"); got != 0 {
		t.Fatalf("public timestamps recorded %d durable per-token events", got)
	}
	if _, err := a.Timestamp(t.Context(), crypto.SHA256Sum([]byte("audit anchor"))); err != nil {
		t.Fatal(err)
	}
	if got := recorder.Count("tsa.timestamp.issued"); got != 1 {
		t.Fatalf("internal timestamp recorded %d durable events, want 1", got)
	}
}
