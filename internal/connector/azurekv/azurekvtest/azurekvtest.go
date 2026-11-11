// SPDX-License-Identifier: BUSL-1.1

// Package azurekvtest is a faithful in-process double of the Azure Key Vault
// certificate endpoints the azurekv connector uses, for testing it without a
// real vault. It is an httptest.Server that requires the expected Entra ID
// (AAD) bearer token. PUT /certificates/{name}/import decodes the base64 PEM
// bundle and records it as a new version of that certificate, as Key Vault
// keeps every imported version and serves the newest by name. It also serves
// what a rollback and a readback read (A166-L1): GET /certificates/{name} (the
// current version), GET /certificates/{name}/versions, GET
// /certificates/{name}/{version} (each with its DER as "cer"), and GET
// /secrets/{name}/{version}, which returns the version's key and chain only
// when the import's policy left the key exportable (Key Vault answers 403
// otherwise). No crypto/* (AN-3): the imported value is a PEM bundle, decoded
// as plain bytes.
package azurekvtest

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
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
	// Version is the version id the import created.
	Version string
	// Exportable is the import policy's key_props.exportable (Key Vault's
	// default for an import, true, when the policy does not say).
	Exportable bool
}

// Server is a fake Key Vault certificate-import endpoint.
type Server struct {
	srv   *httptest.Server
	token string

	mu       sync.Mutex
	versions map[string][]Imported // certificate name -> every imported version, oldest first
	calls    int
	preview  int
	secrets  int
}

// New starts a fake vault that accepts requests bearing expectedToken.
func New(expectedToken string) *Server {
	s := &Server{token: expectedToken, versions: map[string][]Imported{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// URL is the vault base URL.
func (s *Server) URL() string { return s.srv.URL }

// Client returns an HTTP client for the fake vault.
func (s *Server) Client() *http.Client { return s.srv.Client() }

// Close shuts the server down.
func (s *Server) Close() { s.srv.Close() }

// Imported returns the certificate's current version: the newest import.
func (s *Server) Imported(name string) (Imported, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions := s.versions[name]
	if len(versions) == 0 {
		return Imported{}, false
	}
	return versions[len(versions)-1], true
}

// Versions returns every version imported under the certificate name, oldest
// first.
func (s *Server) Versions(name string) []Imported {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Imported(nil), s.versions[name]...)
}

// SecretReads is the number of version secrets served (a rollback reads one).
func (s *Server) SecretReads() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.secrets
}

// Calls is the number of authenticated import calls served.
func (s *Server) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// PreviewCalls is the number of authenticated read-only certificate lists.
func (s *Server) PreviewCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.preview
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+s.token {
		s.fail(w, http.StatusUnauthorized, "Unauthorized", "bearer token missing or invalid")
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/certificates" {
		if r.URL.Query().Get("api-version") == "" {
			s.fail(w, http.StatusBadRequest, "BadParameter", "api-version is required")
			return
		}
		s.mu.Lock()
		s.preview++
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":[]}`))
		return
	}
	if r.Method == http.MethodGet && (strings.HasPrefix(r.URL.Path, "/certificates/") || strings.HasPrefix(r.URL.Path, "/secrets/")) {
		if r.URL.Query().Get("api-version") == "" {
			s.fail(w, http.StatusBadRequest, "BadParameter", "api-version is required")
			return
		}
		s.get(w, r)
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
			KeyProps *struct {
				Exportable *bool `json:"exportable"`
			} `json:"key_props"`
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

	exportable := true
	if in.Policy.KeyProps != nil && in.Policy.KeyProps.Exportable != nil {
		exportable = *in.Policy.KeyProps.Exportable
	}
	s.mu.Lock()
	s.calls++
	version := fmt.Sprintf("%032x", len(s.versions[name])+1)
	s.versions[name] = append(s.versions[name], Imported{PEM: pem, ContentType: in.Policy.SecretProps.ContentType, Version: version, Exportable: exportable})
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"id": s.srv.URL + "/certificates/" + name + "/" + version,
	})
}

// get serves the certificate and secret reads: the current version, the
// version list, one version, and one version's secret.
func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(parts) < 2 || len(parts) > 3 {
		s.fail(w, http.StatusNotFound, "ResourceNotFound", "no such operation")
		return
	}
	versions := s.versions[parts[1]]
	find := func(version string) (Imported, bool) {
		for _, v := range versions {
			if v.Version == version {
				return v, true
			}
		}
		return Imported{}, false
	}
	switch {
	case parts[0] == "certificates" && len(parts) == 2:
		if len(versions) == 0 {
			s.fail(w, http.StatusNotFound, "CertificateNotFound", "certificate not found")
			return
		}
		s.writeBundle(w, parts[1], versions[len(versions)-1])
	case parts[0] == "certificates" && parts[2] == "versions":
		items := make([]map[string]string, 0, len(versions))
		for i := len(versions) - 1; i >= 0; i-- {
			items = append(items, map[string]string{"id": s.srv.URL + "/certificates/" + parts[1] + "/" + versions[i].Version})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"value": items, "nextLink": nil})
	case parts[0] == "certificates":
		v, ok := find(parts[2])
		if !ok {
			s.fail(w, http.StatusNotFound, "CertificateNotFound", "certificate version not found")
			return
		}
		s.writeBundle(w, parts[1], v)
	case parts[0] == "secrets" && len(parts) == 3:
		v, ok := find(parts[2])
		if !ok {
			s.fail(w, http.StatusNotFound, "SecretNotFound", "secret version not found")
			return
		}
		if !v.Exportable {
			s.fail(w, http.StatusForbidden, "Forbidden", "the certificate's key is not exportable")
			return
		}
		s.secrets++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"id": s.srv.URL + "/secrets/" + parts[1] + "/" + v.Version, "value": string(v.PEM), "contentType": v.ContentType,
		})
	default:
		s.fail(w, http.StatusNotFound, "ResourceNotFound", "no such operation")
	}
}

// writeBundle answers a certificate version: its id and its leaf's DER.
func (s *Server) writeBundle(w http.ResponseWriter, name string, v Imported) {
	var leaf []byte
	for rest := v.PEM; ; {
		block, more := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			leaf = block.Bytes
			break
		}
		rest = more
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"id": s.srv.URL + "/certificates/" + name + "/" + v.Version, "cer": base64.StdEncoding.EncodeToString(leaf),
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
