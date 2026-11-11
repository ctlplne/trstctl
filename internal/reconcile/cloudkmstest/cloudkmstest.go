// SPDX-License-Identifier: BUSL-1.1

// Package cloudkmstest holds in-process doubles of the Cloud KMS and Key
// Vault reads the A168-L1 reconcile sources use, written from the providers'
// REST references: Cloud KMS lists a key ring's crypto keys and a key's
// versions one item a page behind nextPageToken; Key Vault lists keys, a
// key's versions and deleted keys one item a page behind an absolute
// nextLink. Both require the expected bearer token.
package cloudkmstest

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// GCPVersion is one crypto key version.
type GCPVersion struct {
	Number    int
	State     string // ENABLED, DISABLED, DESTROY_SCHEDULED, DESTROYED
	Algorithm string
}

// GCPKey is one crypto key in the ring.
type GCPKey struct {
	ID             string
	Labels         map[string]string
	RotationPeriod string
	Versions       []GCPVersion
}

// GCP is the Cloud KMS double.
type GCP struct {
	srv     *httptest.Server
	keyRing string
	token   string

	mu   sync.Mutex
	keys map[string]*GCPKey
	gets int
}

// NewGCP starts a Cloud KMS double for keyRing
// (projects/P/locations/L/keyRings/R) that accepts token.
func NewGCP(keyRing, token string) *GCP {
	g := &GCP{keyRing: keyRing, token: token, keys: map[string]*GCPKey{}}
	g.srv = httptest.NewServer(http.HandlerFunc(g.handle))
	return g
}

// URL is the endpoint base URL; Close stops the double.
func (g *GCP) URL() string { return g.srv.URL }

// Close stops the double.
func (g *GCP) Close() { g.srv.Close() }

// Put adds or replaces a key.
func (g *GCP) Put(key GCPKey) {
	g.mu.Lock()
	defer g.mu.Unlock()
	k := key
	g.keys[key.ID] = &k
}

// SetState sets one version's state, as an operator acting in the console
// would.
func (g *GCP) SetState(keyID string, version int, state string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if key := g.keys[keyID]; key != nil {
		for i := range key.Versions {
			if key.Versions[i].Number == version {
				key.Versions[i].State = state
			}
		}
	}
}

// VersionName is the resource name of a key's version.
func (g *GCP) VersionName(keyID string, version int) string {
	return g.keyRing + "/cryptoKeys/" + keyID + "/cryptoKeyVersions/" + strconv.Itoa(version)
}

// Gets is the number of authenticated reads served.
func (g *GCP) Gets() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.gets
}

func (g *GCP) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+g.token {
		writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{"code": 401, "status": "UNAUTHENTICATED"}})
		return
	}
	if r.Method != http.MethodGet {
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]any{"error": map[string]any{"code": 405}})
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gets++
	page, _ := strconv.Atoi(r.URL.Query().Get("pageToken"))
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	var items []any
	var field string
	switch {
	case path == g.keyRing+"/cryptoKeys":
		field = "cryptoKeys"
		ids := make([]string, 0, len(g.keys))
		for id := range g.keys {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			key := g.keys[id]
			items = append(items, map[string]any{"name": g.keyRing + "/cryptoKeys/" + id, "purpose": "ASYMMETRIC_SIGN",
				"labels": key.Labels, "rotationPeriod": key.RotationPeriod})
		}
	case strings.HasPrefix(path, g.keyRing+"/cryptoKeys/") && strings.HasSuffix(path, "/cryptoKeyVersions"):
		field = "cryptoKeyVersions"
		id := strings.TrimSuffix(strings.TrimPrefix(path, g.keyRing+"/cryptoKeys/"), "/cryptoKeyVersions")
		key := g.keys[id]
		if key == nil {
			writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": 404, "status": "NOT_FOUND"}})
			return
		}
		for _, v := range key.Versions {
			items = append(items, map[string]any{"name": g.VersionName(id, v.Number), "state": v.State, "algorithm": v.Algorithm})
		}
	default:
		writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": 404, "status": "NOT_FOUND"}})
		return
	}
	out := map[string]any{}
	if page < len(items) {
		out[field] = []any{items[page]}
	}
	if page+1 < len(items) {
		out["nextPageToken"] = strconv.Itoa(page + 1)
	}
	writeJSONStatus(w, http.StatusOK, out)
}

// AzureKey is one Key Vault key with its versions.
type AzureKey struct {
	Name     string
	Tags     map[string]string
	Versions []AzureVersion
	// Deleted keys are listed under deletedkeys only.
	Deleted bool
}

// AzureVersion is one key version: an EC key names its curve (Crv), an RSA
// key its modulus size (RSABits).
type AzureVersion struct {
	ID      string
	Enabled bool
	Crv     string
	RSABits int
}

// jwk is the public key a version's bundle carries.
func (a *Azure) jwk(name string, v AzureVersion) map[string]any {
	key := map[string]any{"kid": a.Kid(name, v.ID)}
	if v.RSABits > 0 {
		modulus := make([]byte, v.RSABits/8)
		modulus[0] = 0x80
		key["kty"], key["n"], key["e"] = "RSA", base64.RawURLEncoding.EncodeToString(modulus), "AQAB"
		return key
	}
	key["kty"], key["crv"] = "EC", v.Crv
	return key
}

// Azure is the Key Vault double.
type Azure struct {
	srv   *httptest.Server
	token string

	mu   sync.Mutex
	keys map[string]*AzureKey
	gets int
	// foreignNextLink, when set, replaces nextLink's base URL.
	foreignNextLink string
}

// NewAzure starts a Key Vault double that accepts token.
func NewAzure(token string) *Azure {
	a := &Azure{token: token, keys: map[string]*AzureKey{}}
	a.srv = httptest.NewServer(http.HandlerFunc(a.handle))
	return a
}

// URL is the vault URL.
func (a *Azure) URL() string { return a.srv.URL }

// Close stops the double.
func (a *Azure) Close() { a.srv.Close() }

// Put adds or replaces a key.
func (a *Azure) Put(key AzureKey) {
	a.mu.Lock()
	defer a.mu.Unlock()
	k := key
	a.keys[key.Name] = &k
}

// SetEnabled enables or disables one version.
func (a *Azure) SetEnabled(name, version string, enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if key := a.keys[name]; key != nil {
		for i := range key.Versions {
			if key.Versions[i].ID == version {
				key.Versions[i].Enabled = enabled
			}
		}
	}
}

// SetForeignNextLink makes nextLink point at another host.
func (a *Azure) SetForeignNextLink(base string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.foreignNextLink = base
}

// Kid is the key identifier of a version.
func (a *Azure) Kid(name, version string) string { return a.srv.URL + "/keys/" + name + "/" + version }

// Gets is the number of authenticated reads served.
func (a *Azure) Gets() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.gets
}

func (a *Azure) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+a.token {
		writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{"code": "Unauthorized"}})
		return
	}
	if r.Method != http.MethodGet || r.URL.Query().Get("api-version") == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": map[string]any{"code": "BadParameter"}})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gets++
	page, _ := strconv.Atoi(r.URL.Query().Get("$skiptoken"))
	names := make([]string, 0, len(a.keys))
	for name := range a.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var items []any
	switch {
	case len(parts) == 1 && parts[0] == "keys":
		for _, name := range names {
			key := a.keys[name]
			if key.Deleted || len(key.Versions) == 0 {
				continue
			}
			latest := key.Versions[len(key.Versions)-1]
			items = append(items, map[string]any{"kid": a.srv.URL + "/keys/" + name, "tags": key.Tags,
				"attributes": map[string]any{"enabled": latest.Enabled}})
		}
	case len(parts) == 3 && parts[0] == "keys" && parts[2] == "versions":
		key := a.keys[parts[1]]
		if key == nil || key.Deleted {
			writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "KeyNotFound"}})
			return
		}
		for _, v := range key.Versions {
			items = append(items, map[string]any{"kid": a.Kid(key.Name, v.ID), "tags": key.Tags, "attributes": map[string]any{"enabled": v.Enabled}})
		}
	case len(parts) == 3 && parts[0] == "keys" && parts[2] != "versions":
		key := a.keys[parts[1]]
		if key == nil || key.Deleted {
			writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "KeyNotFound"}})
			return
		}
		for _, v := range key.Versions {
			if v.ID == parts[2] {
				writeJSONStatus(w, http.StatusOK, map[string]any{"key": a.jwk(key.Name, v), "attributes": map[string]any{"enabled": v.Enabled}, "tags": key.Tags})
				return
			}
		}
		writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "KeyNotFound"}})
		return
	case len(parts) == 2 && parts[0] == "deletedkeys":
		key := a.keys[parts[1]]
		if key == nil || !key.Deleted || len(key.Versions) == 0 {
			writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "KeyNotFound"}})
			return
		}
		latest := key.Versions[len(key.Versions)-1]
		writeJSONStatus(w, http.StatusOK, map[string]any{"key": a.jwk(key.Name, latest), "recoveryId": a.srv.URL + "/deletedkeys/" + key.Name,
			"attributes": map[string]any{"enabled": latest.Enabled}, "tags": key.Tags})
		return
	case len(parts) == 1 && parts[0] == "deletedkeys":
		for _, name := range names {
			key := a.keys[name]
			if !key.Deleted || len(key.Versions) == 0 {
				continue
			}
			latest := key.Versions[len(key.Versions)-1]
			items = append(items, map[string]any{"kid": a.srv.URL + "/keys/" + name, "recoveryId": a.srv.URL + "/deletedkeys/" + name, "tags": key.Tags,
				"attributes": map[string]any{"enabled": latest.Enabled, "scheduledPurgeDate": 1893456000}})
		}
	default:
		writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": map[string]any{"code": "NotFound"}})
		return
	}
	out := map[string]any{"value": []any{}}
	if page < len(items) {
		out["value"] = []any{items[page]}
	}
	if page+1 < len(items) {
		base := a.srv.URL
		if a.foreignNextLink != "" {
			base = a.foreignNextLink
		}
		q := url.Values{"api-version": {r.URL.Query().Get("api-version")}, "$skiptoken": {strconv.Itoa(page + 1)}}
		out["nextLink"] = base + r.URL.Path + "?" + q.Encode()
	}
	writeJSONStatus(w, http.StatusOK, out)
}

func writeJSONStatus(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
