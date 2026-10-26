// SPDX-License-Identifier: BUSL-1.1

package ciscotest

import (
	"encoding/pem"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/secretjson"
)

// ISE certificate signing requests (A122). ISE generates the key and the CSR
// itself and names the request with an ID of its own; binding a CA-signed
// certificate to that ID turns the request into a system certificate with the
// key ISE holds. The double generates real keys through the crypto boundary,
// refuses a certificate for any other key, and counts the requests it made, so
// a test can prove a retry reused one instead of leaving an orphan.

const (
	isePathCSR       = "/api/v1/certs/certificate-signing-request"
	isePathCSRExport = "/api/v1/certs/certificate-signing-request/export/"
	isePathBind      = "/api/v1/certs/signed-certificate/bind"
)

type iseCSR struct {
	id     string
	node   string
	key    *crypto.LockedSigner
	csrPEM []byte
}

type iseCSRBody struct {
	Hostnames         []string `json:"hostnames"`
	SubjectCommonName string   `json:"subjectCommonName"`
	SANDNS            []string `json:"sanDNS,omitempty"`
	SANIP             []string `json:"sanIP,omitempty"`
	KeyType           string   `json:"keyType"`
	KeyLength         string   `json:"keyLength"`
	DigestType        string   `json:"digestType"`
	UsedFor           string   `json:"usedFor"`
}

type iseBindBody struct {
	HostName string                 `json:"hostName"`
	ID       string                 `json:"id"`
	Data     secretjson.StringBytes `json:"data"`
	Name     string                 `json:"name"`
	iseRoleBody
}

// CSRsGenerated counts the signing requests ISE generated.
func (s *Server) CSRsGenerated() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.csrCount
}

// PendingCSRs counts the requests not yet bound to a certificate.
func (s *Server) PendingCSRs() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.csrs)
}

// RemoveCSR deletes a pending request, as an administrator might.
func (s *Server) RemoveCSR(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if csr, ok := s.csrs[id]; ok {
		csr.key.Destroy()
		delete(s.csrs, id)
	}
}

// handleISECSR serves ISE's certificate-signing-request calls.
func (s *Server) handleISECSR(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case r.URL.Path == isePathCSR && r.Method == http.MethodPost:
		s.iseGenerateCSR(w, r)
	case strings.HasPrefix(r.URL.Path, isePathCSRExport) && r.Method == http.MethodGet:
		node, id, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, isePathCSRExport), "/")
		node, _ = url.PathUnescape(node)
		id, _ = url.PathUnescape(id)
		s.mu.Lock()
		csr, ok := s.csrs[id]
		s.mu.Unlock()
		if !ok || node != csr.node {
			s.refuse(w, r, http.StatusNotFound, "no such certificate signing request")
			return true
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(csr.csrPEM)
	case r.URL.Path == isePathBind && r.Method == http.MethodPost:
		s.iseBind(w, r)
	default:
		s.refuse(w, r, http.StatusNotFound, "no such resource")
	}
	return true
}

func (s *Server) iseGenerateCSR(w http.ResponseWriter, r *http.Request) {
	var in iseCSRBody
	if !s.decodeStrict(w, r, &in) {
		return
	}
	if len(in.Hostnames) != 1 || in.Hostnames[0] != s.node || strings.TrimSpace(in.SubjectCommonName) == "" ||
		in.KeyType != "ECDSA" || in.KeyLength != "256" || in.DigestType != "SHA-256" || in.UsedFor == "" {
		s.refuse(w, r, http.StatusBadRequest, "hostnames (this node), subjectCommonName, an ECDSA 256 key, SHA-256 and usedFor are required")
		return
	}
	tmpl := crypto.CertificateRequestTemplate{CommonName: in.SubjectCommonName, DNSNames: in.SANDNS}
	for _, raw := range in.SANIP {
		ip := net.ParseIP(raw)
		if ip == nil {
			s.refuse(w, r, http.StatusBadRequest, "invalid sanIP")
			return
		}
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		s.refuse(w, r, http.StatusInternalServerError, "key generation failed")
		return
	}
	csrDER, err := crypto.CreateCertificateRequest(tmpl, key)
	if err != nil {
		key.Destroy()
		s.refuse(w, r, http.StatusBadRequest, "CSR could not be created")
		return
	}
	s.mu.Lock()
	s.csrCount++
	id := "csr-" + strconv.Itoa(s.csrCount)
	if s.csrs == nil {
		s.csrs = map[string]*iseCSR{}
	}
	s.csrs[id] = &iseCSR{id: id, node: s.node, key: key,
		csrPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})}
	s.mu.Unlock()
	s.iseOK(w, map[string]any{"response": []map[string]string{{"id": id, "message": "Successfully generated CSR(s)"}}, "version": "1.0.0"})
}

func (s *Server) iseBind(w http.ResponseWriter, r *http.Request) {
	var in iseBindBody
	if !s.decodeStrict(w, r, &in) {
		return
	}
	if in.HostName != s.node || strings.TrimSpace(in.Name) == "" || !looksPEM(in.Data) {
		s.refuse(w, r, http.StatusBadRequest, "hostName (this node), name and a PEM certificate are required")
		return
	}
	if !s.portalTagged(in.iseRoleBody) {
		s.refuse(w, r, http.StatusBadRequest, "a portal certificate needs a portal group tag")
		return
	}
	s.mu.Lock()
	csr, ok := s.csrs[in.ID]
	matches := false
	if ok {
		info, err := certinfo.Inspect(in.Data)
		matches = err == nil && info.SPKISHA256 == crypto.SHA256Hex(csr.key.Public().DER)
	}
	if !ok || !matches {
		s.mu.Unlock()
		if !ok {
			s.refuse(w, r, http.StatusNotFound, "no such certificate signing request")
		} else {
			s.refuse(w, r, http.StatusBadRequest, "the certificate does not match the request's key")
		}
		return
	}
	s.nextID++
	sc := &SystemCertificate{ID: "sc-" + strconv.Itoa(s.nextID), FriendlyName: in.Name,
		Certificate: append([]byte(nil), in.Data...), DeviceKey: true}
	s.system = append(s.system, sc)
	s.grantRoles(sc, in.roles())
	csr.key.Destroy()
	delete(s.csrs, in.ID)
	s.mu.Unlock()
	s.iseOK(w, map[string]any{"response": []map[string]string{{"id": sc.ID, "message": "Certificate bound"}}})
}
