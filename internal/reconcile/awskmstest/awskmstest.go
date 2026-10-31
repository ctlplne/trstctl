// SPDX-License-Identifier: BUSL-1.1

// Package awskmstest is an in-process AWS KMS stand-in for the read-only
// operations the cloud-KMS authority source calls (A168): ListKeys,
// DescribeKey, ListResourceTags and GetKeyRotationStatus. It verifies every
// request's Signature Version 4 under the configured key, pages ListKeys, and
// counts any other operation so a test can prove nothing was changed.
package awskmstest

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"

	"trstctl.com/trstctl/internal/crypto"
)

// Key is one seeded key.
type Key struct {
	ID       string
	Spec     string // KeySpec, e.g. ECC_NIST_P256
	State    string // Enabled, Disabled, PendingDeletion, ...
	Manager  string // CUSTOMER (default) or AWS
	Tags     map[string]string
	Rotation bool
}

// Server is the stand-in.
type Server struct {
	srv                          *httptest.Server
	region, accessKey, secretKey string
	pageSize                     int
	mu                           sync.Mutex
	keys                         map[string]Key
	calls                        map[string]int
	refused                      int
}

// New starts a stand-in for one region that accepts requests signed with the
// given key and pages ListKeys by pageSize.
func New(region, accessKey, secretKey string, pageSize int) *Server {
	if pageSize <= 0 {
		pageSize = 100
	}
	s := &Server{region: region, accessKey: accessKey, secretKey: secretKey, pageSize: pageSize,
		keys: map[string]Key{}, calls: map[string]int{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

func (s *Server) URL() string          { return s.srv.URL }
func (s *Server) Client() *http.Client { return s.srv.Client() }
func (s *Server) Close()               { s.srv.Close() }

// Put adds or replaces keys.
func (s *Server) Put(keys ...Key) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range keys {
		if k.Manager == "" {
			k.Manager = "CUSTOMER"
		}
		s.keys[k.ID] = k
	}
}

// Calls reports how many times an operation was called.
func (s *Server) Calls(op string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[op]
}

// Mutations counts operations other than the four read-only ones.
func (s *Server) Mutations() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for op, count := range s.calls {
		switch op {
		case "ListKeys", "DescribeKey", "ListResourceTags", "GetKeyRotationStatus":
		default:
			n += count
		}
	}
	return n
}

// Refused counts requests whose signature did not verify.
func (s *Server) Refused() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refused
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if !s.verify(r, body) {
		s.mu.Lock()
		s.refused++
		s.mu.Unlock()
		writeError(w, http.StatusBadRequest, "InvalidSignatureException")
		return
	}
	op := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "TrentService.")
	s.mu.Lock()
	s.calls[op]++
	s.mu.Unlock()
	var in struct {
		KeyID  string `json:"KeyId"`
		Marker string `json:"Marker"`
	}
	_ = json.Unmarshal(body, &in)
	s.mu.Lock()
	defer s.mu.Unlock()
	switch op {
	case "ListKeys":
		ids := make([]string, 0, len(s.keys))
		for id := range s.keys {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		start := 0
		if in.Marker != "" {
			start = sort.SearchStrings(ids, in.Marker)
		}
		end := start + s.pageSize
		if end > len(ids) {
			end = len(ids)
		}
		out := map[string]any{"Keys": []map[string]string{}, "Truncated": end < len(ids)}
		page := make([]map[string]string, 0, end-start)
		for _, id := range ids[start:end] {
			page = append(page, map[string]string{"KeyId": id, "KeyArn": s.arn(id)})
		}
		out["Keys"] = page
		if end < len(ids) {
			out["NextMarker"] = ids[end]
		}
		writeJSON(w, out)
	case "DescribeKey":
		k, ok := s.keys[in.KeyID]
		if !ok {
			writeError(w, http.StatusBadRequest, "NotFoundException")
			return
		}
		writeJSON(w, map[string]any{"KeyMetadata": map[string]any{
			"KeyId": k.ID, "Arn": s.arn(k.ID), "KeyState": k.State, "KeySpec": k.Spec, "KeyManager": k.Manager,
			"Enabled": k.State == "Enabled", "CreationDate": 1.7e9,
		}})
	case "ListResourceTags":
		k, ok := s.keys[in.KeyID]
		if !ok {
			writeError(w, http.StatusBadRequest, "NotFoundException")
			return
		}
		tags := []map[string]string{}
		for key, value := range k.Tags {
			tags = append(tags, map[string]string{"TagKey": key, "TagValue": value})
		}
		writeJSON(w, map[string]any{"Tags": tags, "Truncated": false})
	case "GetKeyRotationStatus":
		k, ok := s.keys[in.KeyID]
		if !ok || k.Spec != "SYMMETRIC_DEFAULT" {
			writeError(w, http.StatusBadRequest, "UnsupportedOperationException")
			return
		}
		writeJSON(w, map[string]any{"KeyRotationEnabled": k.Rotation})
	default:
		writeError(w, http.StatusBadRequest, "UnsupportedOperationException")
	}
}

func (s *Server) arn(id string) string {
	return "arn:aws:kms:" + s.region + ":111122223333:key/" + id
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, kind string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"__type": kind})
}

// verify recomputes the request's Signature Version 4 under the stand-in's key.
func (s *Server) verify(r *http.Request, body []byte) bool {
	const algo = "AWS4-HMAC-SHA256 "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, algo) {
		return false
	}
	cred, signedHeaders, sig := "", "", ""
	for _, f := range strings.Split(auth[len(algo):], ",") {
		f = strings.TrimSpace(f)
		switch {
		case strings.HasPrefix(f, "Credential="):
			cred = strings.TrimPrefix(f, "Credential=")
		case strings.HasPrefix(f, "SignedHeaders="):
			signedHeaders = strings.TrimPrefix(f, "SignedHeaders=")
		case strings.HasPrefix(f, "Signature="):
			sig = strings.TrimPrefix(f, "Signature=")
		}
	}
	scope := strings.SplitN(cred, "/", 2)
	if len(scope) != 2 || scope[0] != s.accessKey || signedHeaders == "" || sig == "" {
		return false
	}
	cs := strings.Split(scope[1], "/")
	if len(cs) != 4 || cs[1] != s.region || cs[2] != "kms" || cs[3] != "aws4_request" {
		return false
	}
	var canonHeaders strings.Builder
	for _, h := range strings.Split(signedHeaders, ";") {
		v := strings.TrimSpace(r.Header.Get(h))
		if h == "host" {
			v = r.Host
		}
		canonHeaders.WriteString(h + ":" + v + "\n")
	}
	canonical := strings.Join([]string{r.Method, r.URL.EscapedPath(), "", canonHeaders.String(), signedHeaders, crypto.SHA256Hex(body)}, "\n")
	toSign := strings.Join([]string{"AWS4-HMAC-SHA256", r.Header.Get("X-Amz-Date"), scope[1], crypto.SHA256Hex([]byte(canonical))}, "\n")
	k := crypto.HMACSHA256([]byte("AWS4"+s.secretKey), []byte(cs[0]))
	k = crypto.HMACSHA256(k, []byte(cs[1]))
	k = crypto.HMACSHA256(k, []byte(cs[2]))
	k = crypto.HMACSHA256(k, []byte("aws4_request"))
	return hex.EncodeToString(crypto.HMACSHA256(k, []byte(toSign))) == sig
}
