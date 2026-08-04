// SPDX-License-Identifier: MPL-2.0

package ciscotest_test

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/connector/cisco/ciscotest"
)

const (
	user = "ers-admin"
	pass = "s3cret-p@ss" // #nosec G101 -- fabricated fixture credential; the test needs the shape, no value is real (CWE-798)
	path = "/api/certificate/import"
)

var validBody = []byte(`{"name":"web-prod",` +
	`"certificate":"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",` +
	`"privateKey":"-----BEGIN PRIVATE KEY-----\ny\n-----END PRIVATE KEY-----\n"}`)

// The double's strictness is the entire reason the connector tests prove
// anything, and nothing in cisco_test.go exercises it: the connector only ever
// sends well-formed requests, so every refusal branch here is invisible from
// there. If a later edit loosened one — dropped the method check, stopped
// requiring PEM, accepted unknown fields — the connector suite would keep
// passing while quietly accepting a request no appliance would take. These
// tests drive the refusals directly so that loosening fails a test instead.
func TestDeviceRefusesRequestsARealApplianceWouldReject(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		ctype  string
		auth   bool
		body   []byte
		status int
	}{
		{"no credentials", http.MethodPost, path, "application/json", false, validBody, http.StatusUnauthorized},
		{"unknown resource", http.MethodPost, "/api/certificate", "application/json", true, validBody, http.StatusNotFound},
		{"wrong method", http.MethodPut, path, "application/json", true, validBody, http.StatusMethodNotAllowed},
		{"form-encoded body", http.MethodPost, path, "application/x-www-form-urlencoded", true, validBody, http.StatusUnsupportedMediaType},
		{"malformed JSON", http.MethodPost, path, "application/json", true, []byte(`{"name":`), http.StatusBadRequest},
		{"unknown field", http.MethodPost, path, "application/json", true,
			[]byte(`{"name":"web-prod","certificate":"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n","privateKey":"-----BEGIN PRIVATE KEY-----\ny\n-----END PRIVATE KEY-----\n","key":"extra"}`),
			http.StatusBadRequest},
		{"no name", http.MethodPost, path, "application/json", true,
			[]byte(`{"name":"","certificate":"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n","privateKey":"-----BEGIN PRIVATE KEY-----\ny\n-----END PRIVATE KEY-----\n"}`),
			http.StatusBadRequest},
		{"certificate is not PEM", http.MethodPost, path, "application/json", true,
			[]byte(`{"name":"web-prod","certificate":"bm90LXBlbQ==","privateKey":"-----BEGIN PRIVATE KEY-----\ny\n-----END PRIVATE KEY-----\n"}`),
			http.StatusBadRequest},
		{"private key is not PEM", http.MethodPost, path, "application/json", true,
			[]byte(`{"name":"web-prod","certificate":"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n","privateKey":"truncated"}`),
			http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := ciscotest.New(user, []byte(pass))
			defer srv.Close()

			resp := do(t, srv, tc.method, tc.path, tc.ctype, tc.auth, tc.body)
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != tc.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			// A refused request must leave no trace on the device. A double that
			// answered with an error but recorded the import anyway would let the
			// connector's "nothing was imported" assertions pass for free.
			if names := srv.ImportedNames(); len(names) != 0 {
				t.Errorf("device imported %v from a request it refused", names)
			}
			refusals := srv.Refusals()
			if len(refusals) != 1 || refusals[0].Status != tc.status {
				t.Fatalf("refusals = %+v, want a single %d", refusals, tc.status)
			}
		})
	}
}

// The happy path is asserted here as well as through the connector, so a failure
// tells you which side broke: a red connector test with this one green is the
// connector, both red is the double.
func TestDeviceAcceptsAWellFormedImport(t *testing.T) {
	srv := ciscotest.New(user, []byte(pass))
	defer srv.Close()

	resp := do(t, srv, http.MethodPost, path, "application/json; charset=utf-8", true, validBody)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if refusals := srv.Refusals(); len(refusals) != 0 {
		t.Errorf("device refused a well-formed import: %+v", refusals)
	}
	got, ok := srv.Imported("web-prod")
	if !ok {
		t.Fatalf("nothing imported; device has %v", srv.ImportedNames())
	}
	if !bytes.HasPrefix(got.Certificate, []byte("-----BEGIN CERTIFICATE-----")) {
		t.Errorf("certificate recorded as %q", got.Certificate)
	}
	if !bytes.HasPrefix(got.PrivateKey, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Error("private key was not recorded as the PEM that was sent")
	}
}

// A wrong password is refused as surely as a missing one. Comparing byte-wise
// rather than through Request.BasicAuth is easy to get subtly wrong (a prefix
// match would accept any password starting with the right one), so both the
// short and long variants are checked.
func TestDeviceRefusesTheWrongPassword(t *testing.T) {
	for _, wrong := range []string{"", "s3cret", pass + "-extra", "S3CRET-P@SS"} {
		srv := ciscotest.New(user, []byte(pass))
		req := request(t, srv, http.MethodPost, path, "application/json", validBody)
		req.SetBasicAuth(user, wrong)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("password %q got status %d, want 401", wrong, resp.StatusCode)
		}
		srv.Close()
	}
}

// FailNext is consumed by exactly one request: a test that injects a failure and
// then deploys again must see the second attempt succeed, or an idempotency test
// built on it would be measuring the injection instead of the connector.
func TestFailNextAppliesOnlyToTheNextImport(t *testing.T) {
	srv := ciscotest.New(user, []byte(pass))
	defer srv.Close()

	srv.FailNext(http.StatusConflict, []byte(`{"error":"name in use"}`))
	first := do(t, srv, http.MethodPost, path, "application/json", true, validBody)
	_ = first.Body.Close()
	if first.StatusCode != http.StatusConflict {
		t.Fatalf("first status = %d, want 409", first.StatusCode)
	}
	if names := srv.ImportedNames(); len(names) != 0 {
		t.Fatalf("an injected failure still imported %v", names)
	}

	second := do(t, srv, http.MethodPost, path, "application/json", true, validBody)
	_ = second.Body.Close()
	if second.StatusCode != http.StatusOK {
		t.Fatalf("second status = %d, want 200", second.StatusCode)
	}
	if _, ok := srv.Imported("web-prod"); !ok {
		t.Error("the import after a consumed failure did not land")
	}
}

// No refusal echoes the request back. The connector's redaction tests assert
// that a credential never reaches an error message; if the double scrubbed the
// body on the device's behalf those tests would pass whatever the connector did.
func TestRefusalsDoNotEchoTheRequest(t *testing.T) {
	srv := ciscotest.New(user, []byte(pass))
	defer srv.Close()

	secretBody := []byte(`{"name":"` + pass + `","certificate":"not-pem","privateKey":"not-pem"}`)
	resp := do(t, srv, http.MethodPost, path, "application/json", true, secretBody)
	defer func() { _ = resp.Body.Close() }()

	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if strings.Contains(buf.String(), pass) {
		t.Errorf("refusal body echoed the submitted credential: %q", buf)
	}
}

func request(t *testing.T, srv *ciscotest.Server, method, p, ctype string, body []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL()+p, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	return req
}

func do(t *testing.T, srv *ciscotest.Server, method, p, ctype string, auth bool, body []byte) *http.Response {
	t.Helper()
	req := request(t, srv, method, p, ctype, body)
	if auth {
		req.SetBasicAuth(user, pass)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}
