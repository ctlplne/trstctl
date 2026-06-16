// Package digicertfake is a faithful in-process test double of the DigiCert
// CertCentral Services API, enough of it to exercise the DigiCert CA plugin
// end-to-end without the real service. It mirrors the documented contract: the
// X-DC-DEVKEY auth header, POST /services/v2/order/certificate/{product}
// returning an order id and certificate_id, GET /services/v2/order/certificate/
// {order_id} reporting status "issued", and GET /services/v2/certificate/
// {certificate_id}/download/format/pem_all returning the raw PEM chain. It signs
// submitted CSRs with a local software authority via the crypto boundary, so it
// holds no crypto/* itself.
package digicertfake

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"time"

	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
)

// devKey is the API key this double accepts in X-DC-DEVKEY.
const devKey = "dc-test-devkey"

type order struct {
	id     int
	certID int
	status string
}

// Server is a running fake CertCentral API.
type Server struct {
	ts        *httptest.Server
	authority *cryptoca.Authority

	mu     sync.Mutex
	orders map[int]*order
	certs  map[int][]byte // certificate_id -> chain PEM
	seq    int
}

// NewServer starts a fake CertCentral API backed by a fresh software CA.
func NewServer() (*Server, error) {
	authority, err := cryptoca.NewAuthority("DigiCert CertCentral Test CA")
	if err != nil {
		return nil, err
	}
	s := &Server{authority: authority, orders: map[int]*order{}, certs: map[int][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /services/v2/order/certificate/{product}", s.handleOrder)
	mux.HandleFunc("GET /services/v2/order/certificate/{orderID}", s.handleOrderInfo)
	mux.HandleFunc("GET /services/v2/certificate/{certID}/download/format/{format}", s.handleDownload)
	s.ts = httptest.NewServer(s.auth(mux))
	return s, nil
}

// URL is the base URL (host root); the plugin appends /services/v2/... paths.
func (s *Server) URL() string { return s.ts.URL }

// APIKey is the key the double accepts.
func (s *Server) APIKey() string { return devKey }

// Close shuts the server down.
func (s *Server) Close() { s.ts.Close() }

// auth enforces X-DC-DEVKEY on every request, as the real Services API does.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-DC-DEVKEY") != devKey {
			writeErr(w, http.StatusForbidden, "access_denied",
				"The API key you are using does not have permission to carry out the request.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleOrder(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Certificate struct {
			CommonName string   `json:"common_name"`
			DNSNames   []string `json:"dns_names"`
			CSR        string   `json:"csr"`
		} `json:"certificate"`
		OrderValidity struct {
			Days  int `json:"days"`
			Years int `json:"years"`
		} `json:"order_validity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request_format", err.Error())
		return
	}
	block, _ := pem.Decode([]byte(body.Certificate.CSR))
	if block == nil {
		writeErr(w, http.StatusBadRequest, "csr_invalid_cannot_parse", "could not parse CSR PEM")
		return
	}
	ttl := time.Duration(body.OrderValidity.Days) * 24 * time.Hour
	if body.OrderValidity.Years > 0 {
		ttl = time.Duration(body.OrderValidity.Years) * 365 * 24 * time.Hour
	}
	if ttl <= 0 {
		ttl = 90 * 24 * time.Hour
	}
	issued, err := s.authority.IssueFromCSR(block.Bytes, ttl)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "csr_invalid_cannot_parse", err.Error())
		return
	}

	s.mu.Lock()
	s.seq++
	orderID := s.seq
	s.seq++
	certID := s.seq
	s.orders[orderID] = &order{id: orderID, certID: certID, status: "issued"}
	s.certs[certID] = issued.CertificatePEM
	s.mu.Unlock()

	// Skip-approval shape: the order id plus the certificate id.
	writeJSON(w, http.StatusCreated, map[string]any{"id": orderID, "certificate_id": certID})
}

func (s *Server) handleOrderInfo(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("orderID"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found|order", "order not found")
		return
	}
	s.mu.Lock()
	o := s.orders[id]
	s.mu.Unlock()
	if o == nil {
		writeErr(w, http.StatusNotFound, "not_found|order", "order not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":          o.id,
		"status":      o.status,
		"certificate": map[string]any{"id": o.certID},
		"product":     map[string]any{"name_id": "ssl_plus"},
	})
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("certID"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "certificate not found")
		return
	}
	switch r.PathValue("format") {
	case "pem_all", "pem_noroot", "pem_nointermediate":
	default:
		writeErr(w, http.StatusBadRequest, "invalid_value:format", "unsupported certificate format")
		return
	}
	s.mu.Lock()
	chain := s.certs[id]
	s.mu.Unlock()
	if chain == nil {
		writeErr(w, http.StatusNotFound, "not_found", "certificate not found")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(chain)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"errors": []map[string]string{{"code": code, "message": message}},
	})
}
