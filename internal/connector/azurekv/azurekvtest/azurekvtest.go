// Package azurekvtest is a faithful in-process double of the Azure Key Vault
// certificate-import endpoint, for testing the azurekv connector without a real
// vault. It is an httptest.Server that requires the expected Entra ID (AAD)
// bearer token, accepts PUT /certificates/{name}/import, decodes the base64 PEM
// bundle, and records it by certificate name so a test can assert the credential
// landed. No crypto/* (AN-3): the imported value is a PEM bundle, decoded as
// plain bytes.
package azurekvtest

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// Imported is a certificate the fake vault received.
type Imported struct {
	PEM         []byte
	ContentType string
}

// Server is a fake Key Vault certificate-import endpoint.
type Server struct {
	srv   *httptest.Server
	token string

	mu    sync.Mutex
	certs map[string]Imported // certificate name -> imported bundle
	calls int
}

// New starts a fake vault that accepts requests bearing expectedToken.
func New(expectedToken string) *Server {
	s := &Server{token: expectedToken, certs: map[string]Imported{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// URL is the vault base URL.
func (s *Server) URL() string { return s.srv.URL }

// Client returns an HTTP client for the fake vault.
func (s *Server) Client() *http.Client { return s.srv.Client() }

// Close shuts the server down.
func (s *Server) Close() { s.srv.Close() }

// Imported returns the bundle imported under the certificate name.
func (s *Server) Imported(name string) (Imported, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.certs[name]
	return v, ok
}

// Calls is the number of authenticated import calls served.
func (s *Server) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		s.fail(w, http.StatusUnauthorized, "Unauthorized", "bearer token missing or invalid")
		return
	}
	name, ok := importName(r.URL.Path)
	if !ok || r.Method != http.MethodPut {
		s.fail(w, http.StatusNotFound, "ResourceNotFound", "no such operation")
		return
	}
	if r.URL.Query().Get("api-version") == "" {
		s.fail(w, http.StatusBadRequest, "BadParameter", "api-version is required")
		return
	}
	body, _ := io.ReadAll(r.Body)
	var in struct {
		Value  string `json:"value"`
		Policy struct {
			SecretProps struct {
				ContentType string `json:"contentType"`
			} `json:"secret_props"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Value == "" {
		s.fail(w, http.StatusBadRequest, "BadParameter", "value is required")
		return
	}
	pem, err := base64.StdEncoding.DecodeString(in.Value)
	if err != nil {
		s.fail(w, http.StatusBadRequest, "BadParameter", "value must be base64")
		return
	}

	s.mu.Lock()
	s.calls++
	s.certs[name] = Imported{PEM: pem, ContentType: in.Policy.SecretProps.ContentType}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"id": s.srv.URL + "/certificates/" + name + "/" + "0123456789abcdef",
	})
}

// importName extracts {name} from /certificates/{name}/import.
func importName(path string) (string, bool) {
	const prefix = "/certificates/"
	const suffix = "/import"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", false
	}
	name := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	if name == "" || strings.Contains(name, "/") {
		return "", false
	}
	return name, true
}

func (s *Server) fail(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": msg}})
}
