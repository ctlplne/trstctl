// SPDX-License-Identifier: MPL-2.0

package clusterfuzz

import (
	"testing"

	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

// On success every identifier must be a non-empty dns identifier.

func FuzzParseFinalizeRequest(f *testing.F) {
	f.Add([]byte(`{"csr":"MIIBAg"}`))
	f.Add([]byte(`{"csr":""}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`garbage`))
	f.Fuzz(func(t *testing.T, data []byte) {
		der, err := acmesrv.ParseFinalizeRequest(data)
		if err != nil {
			return
		}
		if len(der) == 0 {
			t.Fatalf("accepted an empty CSR with nil error from %q", data)
		}
	})
}

func FuzzParseKeyChangeInner(f *testing.F) {
	f.Add([]byte(`{"account":"u","oldKey":{"kty":"RSA"}}`))
	f.Add([]byte(`{"account":""}`))
	f.Add([]byte(`{"oldKey":{}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		kc, err := acmesrv.ParseKeyChangeInner(data)
		if err != nil {
			return
		}
		if kc.Account == "" || len(kc.OldKey) == 0 {
			t.Fatalf("accepted an incomplete keyChange inner from %q: %+v", data, kc)
		}
	})
}

func FuzzParseOrderRequest(f *testing.F) {
	f.Add([]byte(`{"identifiers":[{"type":"dns","value":"example.com"}]}`))
	f.Add([]byte(`{"identifiers":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"identifiers":[{"type":"dns","value":"x"}],"replaces":"abc"}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"identifiers":[{"type":"dns","value":""}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := acmesrv.ParseOrderRequest(data)
		if err != nil {
			return
		}

		if len(req.Identifiers) == 0 {
			t.Fatalf("accepted an order with no identifiers: %q", data)
		}
		for _, id := range req.Identifiers {
			if id.Type != "dns" || id.Value == "" {
				t.Fatalf("accepted a bad identifier %+v from %q", id, data)
			}
		}
	})
}

func FuzzParseRevokeRequest(f *testing.F) {
	f.Add([]byte(`{"certificate":"MIIBAg","reason":1}`))
	f.Add([]byte(`{"certificate":""}`))
	f.Add([]byte(`{"certificate":"MIIBAg","reason":-5}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`garbage`))
	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := acmesrv.ParseRevokeRequest(data)
		if err != nil {
			return
		}
		if len(req.CertDER) == 0 {
			t.Fatalf("accepted an empty certificate with nil error from %q", data)
		}
		if req.Reason < 0 {
			t.Fatalf("accepted a negative reason from %q", data)
		}
	})
}
