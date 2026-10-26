// SPDX-License-Identifier: BUSL-1.1

package ciscotest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/secretjson"
)

// ISE OpenAPI system certificates (A122, owner decision 2026-10-26).
//
// The double also models the ISE OpenAPI calls a target with node_hostname and
// certificate_roles uses: importing a system certificate under a friendly name
// with the roles it serves, listing one node's system certificates, and moving
// roles to another certificate. A role belongs to one certificate per node, so
// granting it to one takes it from the other, as ISE does.
//
// Fidelity gap: these paths and fields follow ISE's published OpenAPI as far as
// this package can establish without hardware. The import call names no node;
// the double applies it to its one node, the node whose API the connector's
// endpoint reaches. A passing test proves the sequence, the naming, the role
// moves and that a failure is surfaced, not that an ISE release accepts these
// exact bodies.

// ISE role keys, as a target names them, and the usage names ISE reports. The
// connector holds its own copy on purpose: a double that imported the
// connector's table would agree with it whatever it said.
var iseUsageNames = map[string]string{
	"admin":  "Admin",
	"eap":    "EAP Authentication",
	"radius": "RADIUS DTLS",
	"pxgrid": "pxGrid",
	"portal": "Portal",
	"saml":   "SAML",
	"ims":    "ISE Messaging Service",
}

const (
	isePathImport = "/api/v1/certs/system-certificate/import"
	isePathSystem = "/api/v1/certs/system-certificate/"
)

// SystemCertificate is one certificate in the node's system store.
type SystemCertificate struct {
	ID           string
	FriendlyName string
	Certificate  []byte
	PrivateKey   []byte
	// Roles are the role keys this certificate serves.
	Roles []string
	// DeviceKey is true when ISE generated the key itself (a CSR it signed).
	DeviceKey bool
}

type iseRoleBody struct {
	Admin                          bool   `json:"admin"`
	EAP                            bool   `json:"eap"`
	RADIUS                         bool   `json:"radius"`
	PxGrid                         bool   `json:"pxgrid"`
	Portal                         bool   `json:"portal"`
	SAML                           bool   `json:"saml"`
	IMS                            bool   `json:"ims"`
	PortalGroupTag                 string `json:"portalGroupTag,omitempty"`
	AllowReplacementOfCertificates bool   `json:"allowReplacementOfCertificates"`
}

func (b iseRoleBody) roles() []string {
	var out []string
	for key, on := range map[string]bool{"admin": b.Admin, "eap": b.EAP, "radius": b.RADIUS, "pxgrid": b.PxGrid,
		"portal": b.Portal, "saml": b.SAML, "ims": b.IMS} {
		if on {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

type iseImportBody struct {
	Name           string                 `json:"name"`
	Data           secretjson.StringBytes `json:"data"`
	PrivateKeyData secretjson.StringBytes `json:"privateKeyData"`
	iseRoleBody
}

type iseUpdateBody struct {
	Name string `json:"name"`
	iseRoleBody
}

// Node is the ISE node this double serves.
func (s *Server) Node() string { return s.node }

// SystemCertificates lists the node's system certificates in import order.
func (s *Server) SystemCertificates() []SystemCertificate {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SystemCertificate, 0, len(s.system))
	for _, sc := range s.system {
		cp := *sc
		cp.Roles = append([]string(nil), sc.Roles...)
		out = append(out, cp)
	}
	return out
}

// RoleHolder reports the friendly name of the certificate serving role.
func (s *Server) RoleHolder(role string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sc := range s.system {
		if containsRole(sc.Roles, role) {
			return sc.FriendlyName
		}
	}
	return ""
}

// RemoveSystemCertificate deletes a system certificate by friendly name, as an
// administrator might, so a test can model a predecessor that is gone.
func (s *Server) RemoveSystemCertificate(friendlyName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, sc := range s.system {
		if sc.FriendlyName == friendlyName {
			s.system = append(s.system[:i], s.system[i+1:]...)
			return
		}
	}
}

// handleISE serves the ISE OpenAPI paths; handled is false for any other path.
func (s *Server) handleISE(w http.ResponseWriter, r *http.Request) (handled bool) {
	path := r.URL.Path
	switch {
	case path == isePathImport:
		s.iseImport(w, r)
	case strings.HasPrefix(path, isePathSystem):
		rest := strings.TrimPrefix(path, isePathSystem)
		node, id, hasID := strings.Cut(rest, "/")
		node, _ = url.PathUnescape(node)
		if node != s.node {
			s.refuse(w, r, http.StatusNotFound, "no such node")
			return true
		}
		switch {
		case !hasID && r.Method == http.MethodGet:
			s.iseList(w, r)
		case hasID && r.Method == http.MethodPut:
			s.iseUpdate(w, r, id)
		default:
			s.refuse(w, r, http.StatusMethodNotAllowed, "method not allowed")
		}
	default:
		return s.handleISECSR(w, r)
	}
	return true
}

func (s *Server) iseImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !jsonContentType(r.Header.Get("Content-Type")) {
		s.refuse(w, r, http.StatusBadRequest, "POST application/json required")
		return
	}
	var in iseImportBody
	if !s.decodeStrict(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" || !looksPEM(in.Data) || !looksPEM(in.PrivateKeyData) {
		s.refuse(w, r, http.StatusBadRequest, "name, data and privateKeyData are required as PEM")
		return
	}
	if !s.portalTagged(in.iseRoleBody) {
		s.refuse(w, r, http.StatusBadRequest, "a portal certificate needs a portal group tag")
		return
	}
	s.mu.Lock()
	sc := s.systemByName(in.Name)
	if sc == nil {
		s.nextID++
		sc = &SystemCertificate{ID: "sc-" + strconv.Itoa(s.nextID), FriendlyName: in.Name}
		s.system = append(s.system, sc)
	}
	sc.Certificate = append([]byte(nil), in.Data...)
	sc.PrivateKey = append([]byte(nil), in.PrivateKeyData...)
	s.grantRoles(sc, in.roles())
	id := sc.ID
	s.mu.Unlock()
	s.iseOK(w, map[string]any{"response": map[string]string{"id": id, "message": "Certificate imported"}})
}

func (s *Server) iseList(w http.ResponseWriter, r *http.Request) {
	page, size := 1, 20
	if v, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && v > 0 {
		page = v
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("size")); err == nil && v > 0 && v <= 100 {
		size = v
	}
	s.mu.Lock()
	var items []map[string]string
	for i := (page - 1) * size; i < len(s.system) && i < page*size; i++ {
		sc := s.system[i]
		var usage []string
		for _, role := range sc.Roles {
			usage = append(usage, iseUsageNames[role])
		}
		items = append(items, map[string]string{"id": sc.ID, "friendlyName": sc.FriendlyName, "usedBy": strings.Join(usage, ", ")})
	}
	s.mu.Unlock()
	if items == nil {
		items = []map[string]string{}
	}
	s.iseOK(w, map[string]any{"response": items, "version": "1.0.0"})
}

func (s *Server) iseUpdate(w http.ResponseWriter, r *http.Request, id string) {
	var in iseUpdateBody
	if !s.decodeStrict(w, r, &in) {
		return
	}
	if !s.portalTagged(in.iseRoleBody) {
		s.refuse(w, r, http.StatusBadRequest, "a portal certificate needs a portal group tag")
		return
	}
	s.mu.Lock()
	var sc *SystemCertificate
	for _, candidate := range s.system {
		if candidate.ID == id {
			sc = candidate
		}
	}
	if sc == nil {
		s.mu.Unlock()
		s.refuse(w, r, http.StatusNotFound, "no such system certificate")
		return
	}
	s.grantRoles(sc, in.roles())
	s.mu.Unlock()
	s.iseOK(w, map[string]any{"response": map[string]string{"id": id, "message": "Certificate updated"}})
}

// grantRoles makes sc serve roles, taking each from any other certificate on
// the node. The caller holds s.mu.
func (s *Server) grantRoles(sc *SystemCertificate, roles []string) {
	for _, role := range roles {
		for _, other := range s.system {
			if other != sc {
				other.Roles = removeRole(other.Roles, role)
			}
		}
		if !containsRole(sc.Roles, role) {
			sc.Roles = append(sc.Roles, role)
		}
	}
	sort.Strings(sc.Roles)
}

func (s *Server) portalTagged(b iseRoleBody) bool {
	return !b.Portal || strings.TrimSpace(b.PortalGroupTag) != ""
}

// systemByName finds a system certificate by friendly name. The caller holds s.mu.
func (s *Server) systemByName(name string) *SystemCertificate {
	for _, sc := range s.system {
		if sc.FriendlyName == name {
			return sc
		}
	}
	return nil
}

func (s *Server) decodeStrict(w http.ResponseWriter, r *http.Request, out any) bool {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		s.refuse(w, r, http.StatusBadRequest, "unreadable body")
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		s.refuse(w, r, http.StatusBadRequest, fmt.Sprintf("malformed JSON body (%T)", out))
		return false
	}
	return true
}

func (s *Server) iseOK(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

func containsRole(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

func removeRole(roles []string, role string) []string {
	out := roles[:0]
	for _, r := range roles {
		if r != role {
			out = append(out, r)
		}
	}
	return out
}
