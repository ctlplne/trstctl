// SPDX-License-Identifier: BUSL-1.1

package clusterfuzz

import (
	"encoding/json"
	"strings"
	"testing"

	acmesrv "trstctl.com/trstctl/internal/protocols/acme"
)

func FuzzParseAccountUpdateRequest(f *testing.F) {
	for _, seed := range []string{`{}`, `{"contact":[]}`, `{"contact":["mailto:owner@example.test"]}`, `{"status":"deactivated"}`, `null`, `{"contact":[null]}`, `{"status":17}`, `not json`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := acmesrv.ParseAccountUpdateRequest(data)
		if err != nil {
			return
		}
		var raw map[string]json.RawMessage
		if json.Unmarshal(data, &raw) != nil || raw == nil {
			t.Fatal("accepted non-object account update")
		}
		if req.Contact != nil && *req.Contact == nil {
			t.Fatal("accepted null contact list")
		}
		if req.Deactivate {
			var status string
			if json.Unmarshal(raw["status"], &status) != nil || status != "deactivated" {
				t.Fatal("deactivated without explicit status")
			}
		}
	})
}

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
	f.Add([]byte(`{"identifiers":[{"type":"email","value":"alice@example.com"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		req, err := acmesrv.ParseOrderRequest(data)
		if err != nil {
			return
		}

		if len(req.Identifiers) == 0 {
			t.Fatalf("accepted an order with no identifiers: %q", data)
		}
		for _, id := range req.Identifiers {
			if (id.Type != acmesrv.IdentifierDNS && id.Type != acmesrv.IdentifierEmail) || id.Value == "" {
				t.Fatalf("accepted a bad identifier %+v from %q", id, data)
			}
		}
	})
}

// FuzzNormalizeEmailIdentifier: an accepted RFC 8823 email identifier is a
// bounded ASCII dot-atom addr-spec with a lowercase DNS domain, never a
// wildcard, and normalizing it again changes nothing (P15).
func FuzzNormalizeEmailIdentifier(f *testing.F) {
	for _, seed := range []string{"alice@example.com", "Alice.B+tag@Example.COM", "*@example.com", "a@b", "\"q\"@example.com", "a..b@example.com", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := acmesrv.NormalizeEmailIdentifier(raw)
		if err != nil {
			return
		}
		at := strings.LastIndexByte(got, '@')
		if at <= 0 || len(got) > 254 || strings.Contains(got, "*") || got[at+1:] != strings.ToLower(got[at+1:]) {
			t.Fatalf("accepted %q as %q", raw, got)
		}
		if again, err := acmesrv.NormalizeEmailIdentifier(got); err != nil || again != got {
			t.Fatalf("normalizing %q again gave %q, %v", got, again, err)
		}
	})
}

// FuzzExtractEmailResponse: the reply-body extractor never panics, and what
// it returns has no white space and no padding (P15).
func FuzzExtractEmailResponse(f *testing.F) {
	for _, seed := range []string{
		"-----BEGIN ACME RESPONSE-----\r\nLoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowy\r\njxAjEuX0=\r\n-----END ACME RESPONSE-----\r\n",
		"-----BEGIN ACME RESPONSE-----", "-----END ACME RESPONSE----------BEGIN ACME RESPONSE-----", "",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		got, ok := acmesrv.ExtractEmailResponse(body)
		if !ok {
			return
		}
		if got == "" || strings.ContainsAny(got, " \t\r\n") || strings.HasSuffix(got, "=") {
			t.Fatalf("extracted %q from %q", got, body)
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
