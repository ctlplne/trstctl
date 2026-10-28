// SPDX-License-Identifier: BUSL-1.1

// Package s3test serves a small S3-compatible API over httptest for tests:
// path-style PutObject (honoring If-None-Match: * and x-amz-checksum-sha256),
// GetObject and HeadObject (with checksum mode), ListObjectsV2 and
// DeleteObject. Each request must name the server's bucket and carry a SigV4
// authorization for its access key ID. It is a test double: the live proof of
// the object-store target runs against a real store.
package s3test

import (
	"encoding/base64"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/objectstore"
)

// Server is a running fake S3 endpoint.
type Server struct {
	*httptest.Server
	Bucket      string
	AccessKeyID string
	Secret      []byte
	// LockEnabled makes the bucket report S3 Object Lock enabled (A208).
	LockEnabled bool

	mu        sync.Mutex
	objects   map[string]object
	stalls    map[string]chan struct{}
	requests  []string
	overwrite bool
}

type object struct {
	data     []byte
	checksum string
}

// NewServer starts a fake store on a loopback address and stops it when the
// test ends.
func NewServer(t testing.TB) *Server {
	t.Helper()
	s := &Server{
		Bucket: "trstctl-test", AccessKeyID: "AKIATRSTCTLTEST", Secret: []byte("test-secret-access-key"),
		objects: map[string]object{}, stalls: map[string]chan struct{}{},
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// Open returns a store client for this server, destroyed when the test ends.
func (s *Server) Open(t testing.TB, mutate ...func(*objectstore.Options)) *objectstore.S3 {
	t.Helper()
	opts := s.Options()
	for _, m := range mutate {
		m(&opts)
	}
	store, err := objectstore.Open(opts)
	if err != nil {
		t.Fatalf("open the fake object store: %v", err)
	}
	t.Cleanup(store.Destroy)
	return store
}

// Options are the client options that reach this server.
func (s *Server) Options() objectstore.Options {
	return objectstore.Options{
		Endpoint: s.URL, Bucket: s.Bucket, PathStyle: true, AllowInsecureLoopback: true,
		AccessKeyID: s.AccessKeyID, SecretAccessKey: append([]byte(nil), s.Secret...),
	}
}

// Keys lists every stored key, sorted.
func (s *Server) Keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.objects))
	for key := range s.objects {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Object returns a stored object's bytes.
func (s *Server) Object(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.objects[key]
	return append([]byte(nil), o.data...), ok
}

// Seed stores an object directly, as if an earlier client had uploaded it
// with its SHA-256 checksum.
func (s *Server) Seed(key string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = object{data: append([]byte(nil), data...), checksum: base64.StdEncoding.EncodeToString(crypto.SHA256Sum(data))}
}

// Replace overwrites a stored object's bytes behind the client's back, keeping
// the checksum recorded at upload, as a corrupted or tampered store would.
func (s *Server) Replace(key string, data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.objects[key]
	o.data = append([]byte(nil), data...)
	s.objects[key] = o
}

// IgnoreConditionalWrites makes the server replace an existing object even
// when the request says If-None-Match: *, as a store without conditional-write
// support does.
func (s *Server) IgnoreConditionalWrites() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.overwrite = true
}

// Requests lists the requests served so far as "METHOD key".
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// Stall holds every request with this method until release is called.
func (s *Server) Stall(method string) (release func()) {
	ch := make(chan struct{})
	s.mu.Lock()
	s.stalls[method] = ch
	s.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			delete(s.stalls, method)
			s.mu.Unlock()
			close(ch)
		})
	}
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	s.mu.Lock()
	s.requests = append(s.requests, r.Method+" "+key)
	stall := s.stalls[r.Method]
	s.mu.Unlock()
	if stall != nil {
		select {
		case <-stall:
		case <-r.Context().Done():
			return
		}
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential="+s.AccessKeyID+"/") {
		writeError(w, r, http.StatusForbidden, "InvalidAccessKeyId", key)
		return
	}
	if bucket != s.Bucket {
		writeError(w, r, http.StatusNotFound, "NoSuchBucket", key)
		return
	}
	switch {
	case key == "" && r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2":
		s.list(w, r)
	case key == "" && r.Method == http.MethodGet && r.URL.Query().Has("object-lock"):
		s.objectLockConfiguration(w, r)
	case key == "":
		writeError(w, r, http.StatusNotImplemented, "NotImplemented", key)
	case r.Method == http.MethodPut:
		s.put(w, r, key)
	case r.Method == http.MethodGet || r.Method == http.MethodHead:
		s.get(w, r, key)
	case r.Method == http.MethodDelete:
		s.mu.Lock()
		delete(s.objects, key)
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		writeError(w, r, http.StatusNotImplemented, "NotImplemented", key)
	}
}

func (s *Server) put(w http.ResponseWriter, r *http.Request, key string) {
	contentHash := r.Header.Get("X-Amz-Content-Sha256")
	if strings.HasPrefix(contentHash, "STREAMING-") || r.Header.Get("Content-Encoding") == "aws-chunked" {
		writeError(w, r, http.StatusNotImplemented, "NotImplemented", key)
		return
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "IncompleteBody", key)
		return
	}
	if contentHash != "" && contentHash != "UNSIGNED-PAYLOAD" && contentHash != crypto.SHA256Hex(data) {
		writeError(w, r, http.StatusBadRequest, "XAmzContentSHA256Mismatch", key)
		return
	}
	checksum := base64.StdEncoding.EncodeToString(crypto.SHA256Sum(data))
	if claimed := r.Header.Get("X-Amz-Checksum-Sha256"); claimed != "" && claimed != checksum {
		writeError(w, r, http.StatusBadRequest, "BadDigest", key)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.objects[key]; exists && r.Header.Get("If-None-Match") == "*" && !s.overwrite {
		writeError(w, r, http.StatusPreconditionFailed, "PreconditionFailed", key)
		return
	}
	stored := object{data: data}
	if r.Header.Get("X-Amz-Checksum-Sha256") != "" {
		stored.checksum = checksum
	}
	s.objects[key] = stored
	w.Header().Set("ETag", `"`+crypto.SHA256Hex(data)[:32]+`"`)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) get(w http.ResponseWriter, r *http.Request, key string) {
	s.mu.Lock()
	o, ok := s.objects[key]
	s.mu.Unlock()
	if !ok {
		writeError(w, r, http.StatusNotFound, "NoSuchKey", key)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(o.data)))
	w.Header().Set("ETag", `"`+crypto.SHA256Hex(o.data)[:32]+`"`)
	if strings.EqualFold(r.Header.Get("X-Amz-Checksum-Mode"), "ENABLED") && o.checksum != "" {
		w.Header().Set("X-Amz-Checksum-Sha256", o.checksum)
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(o.data)
	}
}

type listResult struct {
	XMLName               xml.Name      `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ListBucketResult"`
	Name                  string        `xml:"Name"`
	Prefix                string        `xml:"Prefix"`
	KeyCount              int           `xml:"KeyCount"`
	MaxKeys               int           `xml:"MaxKeys"`
	IsTruncated           bool          `xml:"IsTruncated"`
	NextContinuationToken string        `xml:"NextContinuationToken,omitempty"`
	Contents              []listContent `xml:"Contents"`
}

type listContent struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	Size         int    `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	prefix := query.Get("prefix")
	maxKeys := 1000
	if raw := query.Get("max-keys"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n < maxKeys {
			maxKeys = n
		}
	}
	after := query.Get("continuation-token")
	result := listResult{Name: s.Bucket, Prefix: prefix, MaxKeys: maxKeys}
	for _, key := range s.Keys() {
		if !strings.HasPrefix(key, prefix) || (after != "" && key <= after) {
			continue
		}
		if len(result.Contents) == maxKeys {
			result.IsTruncated = true
			result.NextContinuationToken = result.Contents[len(result.Contents)-1].Key
			break
		}
		data, _ := s.Object(key)
		result.Contents = append(result.Contents, listContent{
			Key: key, LastModified: time.Unix(0, 0).UTC().Format(time.RFC3339), Size: len(data), StorageClass: "STANDARD",
		})
	}
	result.KeyCount = len(result.Contents)
	w.Header().Set("Content-Type", "application/xml")
	_, _ = io.WriteString(w, xml.Header)
	_ = xml.NewEncoder(w).Encode(result)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, key string) {
	if r.Method == http.MethodHead {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, xml.Header)
	_ = xml.NewEncoder(w).Encode(struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
		Message string   `xml:"Message"`
		Key     string   `xml:"Key,omitempty"`
	}{Code: code, Message: code, Key: key})
}

// objectLockConfiguration answers GetObjectLockConfiguration the way S3 does:
// the configuration when the bucket has Object Lock, else an error.
func (s *Server) objectLockConfiguration(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	enabled := s.LockEnabled
	s.mu.Unlock()
	if !enabled {
		writeError(w, r, http.StatusNotFound, "ObjectLockConfigurationNotFoundError", "")
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	_, _ = io.WriteString(w, xml.Header+`<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`)
}
