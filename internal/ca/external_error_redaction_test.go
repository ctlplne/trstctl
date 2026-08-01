// SPDX-License-Identifier: MPL-2.0

package ca_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/ca"
	"trstctl.com/trstctl/internal/ca/adcs"
	"trstctl.com/trstctl/internal/ca/awspca"
	"trstctl.com/trstctl/internal/ca/azurekv"
	"trstctl.com/trstctl/internal/ca/digicert"
	"trstctl.com/trstctl/internal/ca/ejbca"
	"trstctl.com/trstctl/internal/ca/entrust"
	"trstctl.com/trstctl/internal/ca/gcpcas"
	"trstctl.com/trstctl/internal/ca/globalsign"
	"trstctl.com/trstctl/internal/ca/letsencrypt"
	"trstctl.com/trstctl/internal/ca/sectigo"
	"trstctl.com/trstctl/internal/ca/smallstep"
	"trstctl.com/trstctl/internal/ca/vaultpki"
	"trstctl.com/trstctl/internal/ca/venafi"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
)

const upstreamEcho = "receiver-echoed-token-password-key"

// TestExternalCAProductionResponseReadersStayWipeable is the completeness guard
// for every advertised external-CA package. io.ReadAll/io.Copy may grow or use
// scratch buffers whose old response bytes the caller cannot reach to wipe. A
// hostile CA is allowed to echo a submitted CSR or authority header, so shipped
// adapters must read responses through internal/crypto/secret's owned buffers.
func TestExternalCAProductionResponseReadersStayWipeable(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate external-CA response-buffer guard")
	}
	caRoot := filepath.Dir(thisFile)
	for _, provider := range config.ExternalCATypes {
		dir := filepath.Join(caRoot, provider)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read advertised external-CA package %s: %v", provider, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			source, err := os.ReadFile(path) // #nosec G304 -- test reads its own fixture/tempdir path (CWE-22)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			for _, forbidden := range [][]byte{
				[]byte("io.ReadAll("),
				[]byte("io.Copy("),
				[]byte("io.CopyBuffer("),
			} {
				if bytes.Contains(source, forbidden) {
					t.Errorf("%s uses %s for an upstream response; use secret.ReadBounded or secret.Drain so every observed byte is wipeable", path, forbidden)
				}
			}
		}
	}
}

// echoTransport behaves like a malicious CA or gateway: it reflects configured
// authority material, plus selected JSON credential fields it actually received,
// into every common provider error-envelope shape. Production integrations must
// retain only the HTTP status and let none of these bytes reach errors or logs.
type echoTransport struct {
	echoes      []string
	dynamicKeys []string
	echoed      []string
}

func (t *echoTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	echoed := append([]string(nil), t.echoes...)
	if len(body) != 0 && len(t.dynamicKeys) != 0 {
		var fields map[string]json.RawMessage
		if json.Unmarshal(body, &fields) == nil {
			for _, key := range t.dynamicKeys {
				var value string
				if json.Unmarshal(fields[key], &value) == nil && value != "" {
					echoed = append(echoed, value)
				}
			}
		}
	}
	if len(echoed) == 0 {
		echoed = []string{upstreamEcho}
	}
	t.echoed = append([]string(nil), echoed...)
	message := strings.Join(echoed, " | ")
	responseBody, _ := json.Marshal(map[string]any{
		"error":          map[string]any{"code": "AUTH", "message": message},
		"Error":          message,
		"Message":        message,
		"message":        message,
		"error_message":  message,
		"description":    message,
		"status_details": message,
		"errors":         []string{message},
	})
	return &http.Response{
		StatusCode: http.StatusUnauthorized,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(responseBody)),
		Request:    req,
	}, nil
}

func TestExternalCAReceiverEchoCannotReachErrorOrLog(t *testing.T) {
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "echo.external-ca.test", DNSNames: []string{"echo.external-ca.test"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	request := ca.IssueRequest{
		TenantID: "tenant-echo", CSR: csr, DNSNames: []string{"echo.external-ca.test"},
		TTL: time.Hour, ProviderIdempotencyKey: "echo-provider-idempotency",
	}

	type buildFunc func(*testing.T, *http.Client) (ca.CA, error)
	tests := []struct {
		name        string
		echoes      []string
		dynamicKeys []string
		build       buildFunc
	}{
		{name: "ejbca", echoes: []string{upstreamEcho}, dynamicKeys: []string{"password"}, build: func(_ *testing.T, client *http.Client) (ca.CA, error) {
			return ejbca.New(ejbca.Config{Name: "ejbca", BaseURL: "https://ca.invalid", Token: []byte(upstreamEcho), Password: []byte(upstreamEcho), CAName: "root", CertificateProfile: "tls", EndEntityProfile: "tls"}, ejbca.WithHTTPClient(client)), nil
		}},
		{name: "sectigo", echoes: []string{upstreamEcho}, build: func(_ *testing.T, client *http.Client) (ca.CA, error) {
			return sectigo.New(sectigo.Config{Name: "sectigo", BaseURL: "https://ca.invalid", Login: "operator", Password: []byte(upstreamEcho), CustomerURI: "customer", OrgID: 1, CertType: 1}, sectigo.WithHTTPClient(client)), nil
		}},
		{name: "venafi", echoes: []string{upstreamEcho}, build: func(_ *testing.T, client *http.Client) (ca.CA, error) {
			return venafi.New(venafi.Config{Name: "venafi", BaseURL: "https://ca.invalid", AccessToken: []byte(upstreamEcho), PolicyDN: `\VED\Policy\trstctl`}, venafi.WithHTTPClient(client)), nil
		}},
		{name: "digicert", echoes: []string{upstreamEcho}, build: func(_ *testing.T, client *http.Client) (ca.CA, error) {
			return digicert.New("digicert", "https://ca.invalid", []byte(upstreamEcho), digicert.WithHTTPClient(client)), nil
		}},
		{name: "entrust", echoes: []string{upstreamEcho}, build: func(_ *testing.T, client *http.Client) (ca.CA, error) {
			return entrust.New(entrust.Config{Name: "entrust", BaseURL: "https://ca.invalid", CAID: "root"}, entrust.WithHTTPClient(client)), nil
		}},
		{name: "globalsign", echoes: []string{upstreamEcho}, build: func(_ *testing.T, client *http.Client) (ca.CA, error) {
			return globalsign.New(globalsign.Config{Name: "globalsign", BaseURL: "https://ca.invalid", APIKey: []byte(upstreamEcho), APISecret: []byte(upstreamEcho)}, globalsign.WithHTTPClient(client)), nil
		}},
		{name: "smallstep", dynamicKeys: []string{"ott"}, build: func(_ *testing.T, client *http.Client) (ca.CA, error) {
			return smallstep.New(smallstep.Config{Name: "smallstep", BaseURL: "https://ca.invalid", ProvisionerName: "trstctl", ProvisionerKey: []byte(upstreamEcho)}, smallstep.WithHTTPClient(client)), nil
		}},
		{name: "vaultpki", echoes: []string{upstreamEcho}, build: func(_ *testing.T, client *http.Client) (ca.CA, error) {
			return vaultpki.New(vaultpki.Config{Name: "vaultpki", BaseURL: "https://ca.invalid", Token: []byte(upstreamEcho), Mount: "pki", Role: "web"}, vaultpki.WithHTTPClient(client)), nil
		}},
		{name: "adcs", echoes: []string{upstreamEcho}, build: func(_ *testing.T, client *http.Client) (ca.CA, error) {
			transport, err := adcs.NewWebEnrollmentTransport(adcs.WebEnrollmentConfig{BaseURL: "https://ca.invalid/certsrv", Username: "operator", Password: []byte(upstreamEcho), HTTPClient: client})
			if err != nil {
				return nil, err
			}
			return adcs.New(adcs.Config{Name: "adcs", CAConfig: `HOST\CA`, Template: "WebServer"}, transport), nil
		}},
		{name: "awspca", echoes: []string{upstreamEcho}, build: func(_ *testing.T, client *http.Client) (ca.CA, error) {
			api, err := awspca.NewHTTPAPI(awspca.HTTPConfig{Endpoint: "https://ca.invalid", Region: "us-east-1", AccessKeyID: "AKIATEST", SecretAccessKey: []byte(upstreamEcho), SessionToken: []byte(upstreamEcho), HTTPClient: client})
			if err != nil {
				return nil, err
			}
			return awspca.New(awspca.Config{Name: "awspca", CertificateAuthorityArn: "arn:aws:acm-pca:us-east-1:123456789012:certificate-authority/test"}, api), nil
		}},
		{name: "gcpcas", echoes: []string{upstreamEcho}, build: func(_ *testing.T, client *http.Client) (ca.CA, error) {
			api, err := gcpcas.NewHTTPAPI(gcpcas.HTTPConfig{Endpoint: "https://ca.invalid", BearerToken: []byte(upstreamEcho), HTTPClient: client})
			if err != nil {
				return nil, err
			}
			return gcpcas.New(gcpcas.Config{Name: "gcpcas", CaPool: "projects/p/locations/l/caPools/pool"}, api), nil
		}},
		{name: "azurekv", echoes: []string{upstreamEcho}, build: func(_ *testing.T, client *http.Client) (ca.CA, error) {
			api, err := azurekv.NewHTTPAPI(azurekv.HTTPConfig{BearerToken: []byte(upstreamEcho), HTTPClient: client})
			if err != nil {
				return nil, err
			}
			return azurekv.New(azurekv.Config{Name: "azurekv", VaultBaseURL: "https://ca.invalid", CertificatePrefix: "trstctl"}, api), nil
		}},
		{name: "letsencrypt", echoes: []string{upstreamEcho}, build: func(_ *testing.T, client *http.Client) (ca.CA, error) {
			return letsencrypt.NewPluginWithRemoteAccountSigner("letsencrypt", "https://ca.invalid/directory", client, key)
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := &echoTransport{echoes: test.echoes, dynamicKeys: test.dynamicKeys}
			implementation, err := test.build(t, &http.Client{Transport: transport, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if destroyer, ok := implementation.(interface{ Destroy() }); ok {
				defer destroyer.Destroy()
			}
			_, err = implementation.Issue(context.Background(), request)
			if err == nil {
				t.Fatal("Issue succeeded against receiver echo transport")
			}
			if len(transport.echoed) == 0 {
				t.Fatal("receiver did not echo any authority material")
			}
			var logOutput bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logOutput, nil))
			logger.Error("external CA failed", "error", err)
			for _, echoed := range transport.echoed {
				if echoed == "" {
					continue
				}
				if strings.Contains(err.Error(), echoed) {
					t.Fatalf("error leaked receiver echo %q: %v", echoed, err)
				}
				if strings.Contains(logOutput.String(), echoed) {
					t.Fatalf("log leaked receiver echo %q: %s", echoed, logOutput.String())
				}
			}
			if strings.Contains(fmt.Sprintf("%+v", err), upstreamEcho) {
				t.Fatalf("formatted error leaked upstream echo: %+v", err)
			}
		})
	}
}
