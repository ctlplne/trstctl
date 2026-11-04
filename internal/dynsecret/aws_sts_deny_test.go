// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// iamRolePolicyDouble answers the four IAM role-policy calls for one role the
// way IAM does: GetRolePolicy returns the document URL-encoded, and a missing
// policy is NoSuchEntity. readback, when set, replaces the document returned.
type iamRolePolicyDouble struct {
	t        *testing.T
	mu       sync.Mutex
	role     string
	policies map[string]string
	actions  []string
	readback func(stored string) string
	putFails int
}

func (d *iamRolePolicyDouble) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	action := r.Form.Get("Action")
	d.actions = append(d.actions, action)
	if !strings.Contains(r.Header.Get("Authorization"), "/iam/aws4_request") || r.Form.Get("Version") != "2010-05-08" {
		http.Error(w, "<Error><Code>InvalidClientTokenId</Code></Error>", http.StatusForbidden)
		return
	}
	if r.Form.Get("RoleName") != d.role {
		http.Error(w, "<Error><Code>NoSuchEntity</Code></Error>", http.StatusNotFound)
		return
	}
	name := r.Form.Get("PolicyName")
	switch action {
	case "PutRolePolicy":
		if d.putFails > 0 {
			http.Error(w, "<Error><Code>AccessDenied</Code></Error>", http.StatusForbidden)
			return
		}
		d.policies[name] = r.Form.Get("PolicyDocument")
		_, _ = fmt.Fprint(w, `<PutRolePolicyResponse><ResponseMetadata/></PutRolePolicyResponse>`)
	case "GetRolePolicy":
		stored, ok := d.policies[name]
		if !ok {
			http.Error(w, "<Error><Code>NoSuchEntity</Code></Error>", http.StatusNotFound)
			return
		}
		if d.readback != nil {
			stored = d.readback(stored)
		}
		_, _ = fmt.Fprintf(w, `<GetRolePolicyResponse><GetRolePolicyResult><RoleName>%s</RoleName><PolicyName>%s</PolicyName><PolicyDocument>%s</PolicyDocument></GetRolePolicyResult></GetRolePolicyResponse>`, // #nosec G705 -- test writes fixture bytes to its own recorder/local server (CWE-79)
			d.role, name, url.PathEscape(stored))
	case "ListRolePolicies":
		names := make([]string, 0, len(d.policies))
		for n := range d.policies {
			names = append(names, n)
		}
		sort.Strings(names)
		var b strings.Builder
		for _, n := range names {
			b.WriteString("<member>" + n + "</member>")
		}
		_, _ = fmt.Fprintf(w, `<ListRolePoliciesResponse><ListRolePoliciesResult><PolicyNames>%s</PolicyNames><IsTruncated>false</IsTruncated></ListRolePoliciesResult></ListRolePoliciesResponse>`, b.String())
	case "DeleteRolePolicy":
		if _, ok := d.policies[name]; !ok {
			http.Error(w, "<Error><Code>NoSuchEntity</Code></Error>", http.StatusNotFound)
			return
		}
		delete(d.policies, name)
		_, _ = fmt.Fprint(w, `<DeleteRolePolicyResponse><ResponseMetadata/></DeleteRolePolicyResponse>`)
	default:
		http.Error(w, "unexpected action "+action, http.StatusBadRequest)
	}
}

func (d *iamRolePolicyDouble) names() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	names := make([]string, 0, len(d.policies))
	for n := range d.policies {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (d *iamRolePolicyDouble) count(action string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, a := range d.actions {
		if a == action {
			n++
		}
	}
	return n
}

func newDenyPolicyBackend(t *testing.T, double *iamRolePolicyDouble, optIn bool) *AWSSTSBackend {
	t.Helper()
	server := httptest.NewServer(double)
	t.Cleanup(server.Close)
	backend, err := NewAWSSTSBackend(AWSSTSConfig{
		Endpoint: server.URL, HTTPClient: server.Client(), Region: "us-east-1",
		AccessKeyID: "AKID", SecretAccessKey: []byte("admin-secret"),
		RoleARNs:    map[string]string{"reader": "arn:aws:iam::123456789012:role/trstctl-reader"},
		IAMEndpoint: server.URL, RevokeWithDenyPolicy: optIn,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(backend.Close)
	return backend
}

func stsSessionRef(t *testing.T, assumedRoleID string, expiration time.Time) string {
	t.Helper()
	ref, err := json.Marshal(awsSTSRef{
		RoleARN: "arn:aws:iam::123456789012:role/trstctl-reader", SessionName: strings.SplitN(assumedRoleID, ":", 2)[1],
		AssumedRoleID: assumedRoleID, AccessKeyID: "ASIAEXAMPLE123456", Expiration: expiration,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(ref)
}

// N3: a revoked STS session is denied through its role before it expires. Its
// own inline policy holds one Deny of every action for exactly its
// aws:userid, read back before the revocation counts; the role's other
// policies are left alone and denials of expired sessions are pruned.
func TestAWSSTSRevokeWithDenyPolicyDeniesTheSessionN3(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	expiration := now.Add(time.Hour)
	stale := awsSTSDenyPolicyPrefix + "1000000000-0123456789ab"
	other := AWSSTSDenyPolicyName("AROAREADER:other-lease", now.Add(30*time.Minute))
	double := &iamRolePolicyDouble{t: t, role: "trstctl-reader", policies: map[string]string{
		"app-inline": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
		stale:        `{"Version":"2012-10-17","Statement":[]}`,
		other:        `{"Version":"2012-10-17","Statement":[]}`,
	}}
	backend := newDenyPolicyBackend(t, double, true)
	backend.query.now = func() time.Time { return now }
	ref := stsSessionRef(t, "AROAREADER:trstctl-reader-lease", expiration)

	method, err := backend.RevokeMethod(context.Background(), ref)
	if err != nil || method != RevocationMethodDenyPolicy {
		t.Fatalf("revoke = %q %v", method, err)
	}
	name := AWSSTSDenyPolicyName("AROAREADER:trstctl-reader-lease", expiration)
	if !strings.HasPrefix(name, "trstctl-revoked-"+strconv.FormatInt(expiration.Unix(), 10)+"-") || len(name) > 128 {
		t.Fatalf("policy name %q", name)
	}
	if got, want := strings.Join(double.names(), ","), strings.Join([]string{"app-inline", other, name}, ","); got != want {
		t.Fatalf("role policies = %s, want %s (the expired denial pruned, the rest kept)", got, want)
	}
	var doc struct {
		Statement []awsDenyStatement
	}
	if err := json.Unmarshal([]byte(double.policies[name]), &doc); err != nil || len(doc.Statement) != 1 {
		t.Fatalf("document %s: %v", double.policies[name], err)
	}
	if s := doc.Statement[0]; s.Effect != "Deny" || s.Action != "*" || s.Resource != "*" || len(s.Condition) != 1 ||
		s.Condition["StringEquals"]["aws:userid"] != "AROAREADER:trstctl-reader-lease" {
		t.Fatalf("statement = %+v", s)
	}
	// A retried revocation rewrites the same policy.
	if method, err := backend.RevokeMethod(context.Background(), ref); err != nil || method != RevocationMethodDenyPolicy || len(double.names()) != 3 {
		t.Fatalf("retried revoke = %q %v %v", method, err, double.names())
	}
	// Revoke is RevokeMethod without the method.
	if err := backend.Revoke(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
}

func TestAWSSTSDenyPolicyReadbackMustHoldTheExactDenialN3(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ref := stsSessionRef(t, "AROAREADER:trstctl-reader-lease", now.Add(time.Hour))
	for name, readback := range map[string]func(string) string{
		"another session": func(stored string) string {
			return strings.ReplaceAll(stored, "trstctl-reader-lease", "someone-else")
		},
		"a narrower condition": func(stored string) string {
			return strings.Replace(stored, `"StringEquals"`, `"IpAddress":{"aws:SourceIp":"10.0.0.0/8"},"StringEquals"`, 1)
		},
		"an allow": func(stored string) string { return strings.Replace(stored, `"Deny"`, `"Allow"`, 1) },
		"one action only": func(stored string) string {
			return strings.Replace(stored, `"Action":"*"`, `"Action":["s3:*"]`, 1)
		},
		"no document": func(string) string { return "not json %zz" },
	} {
		t.Run(name, func(t *testing.T) {
			double := &iamRolePolicyDouble{t: t, role: "trstctl-reader", policies: map[string]string{}, readback: readback}
			backend := newDenyPolicyBackend(t, double, true)
			backend.query.now = func() time.Time { return now }
			if method, err := backend.RevokeMethod(context.Background(), ref); err == nil || method != "" {
				t.Fatalf("a readback with %s counted as a denial: %q %v", name, method, err)
			}
		})
	}
	// A refused write is an error, never a denial.
	double := &iamRolePolicyDouble{t: t, role: "trstctl-reader", policies: map[string]string{}, putFails: 1}
	backend := newDenyPolicyBackend(t, double, true)
	backend.query.now = func() time.Time { return now }
	if method, err := backend.RevokeMethod(context.Background(), ref); err == nil || method != "" || double.count("GetRolePolicy") != 0 {
		t.Fatalf("a refused PutRolePolicy = %q %v", method, err)
	}
	// The readback accepts a document that is already JSON, and lists.
	if !awsSTSDenyPolicyHolds([]byte(`<GetRolePolicyResponse><GetRolePolicyResult><PolicyDocument>{"Statement":{"Effect":"Deny","Action":["*"],"Resource":"*","Condition":{"StringEquals":{"aws:UserId":["AROAREADER:trstctl-reader-lease"]}}}}</PolicyDocument></GetRolePolicyResult></GetRolePolicyResponse>`), "AROAREADER:trstctl-reader-lease") {
		t.Fatal("a plain JSON document with list values was not read")
	}
}

func TestAWSSTSDenyPolicyLeavesExpiredSessionsAndOptOutAloneN3(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	// Past its expiry and the clock margin: no denial is written.
	double := &iamRolePolicyDouble{t: t, role: "trstctl-reader", policies: map[string]string{}}
	backend := newDenyPolicyBackend(t, double, true)
	backend.query.now = func() time.Time { return now }
	expired := stsSessionRef(t, "AROAREADER:old-lease", now.Add(-awsSTSDenyClockMargin-time.Second))
	if method, err := backend.RevokeMethod(context.Background(), expired); err != nil || method != RevocationMethodNativeExpiry || double.count("PutRolePolicy") != 0 {
		t.Fatalf("expired session = %q %v (puts %d)", method, err, double.count("PutRolePolicy"))
	}
	// Within the margin a denial is still written.
	recent := stsSessionRef(t, "AROAREADER:recent-lease", now.Add(-time.Minute))
	if method, err := backend.RevokeMethod(context.Background(), recent); err != nil || method != RevocationMethodDenyPolicy {
		t.Fatalf("a session just past expiry = %q %v", method, err)
	}
	// Not opted in: pending until native expiry, and no IAM call at all.
	plain := &iamRolePolicyDouble{t: t, role: "trstctl-reader", policies: map[string]string{}}
	off := newDenyPolicyBackend(t, plain, false)
	off.query.now = func() time.Time { return now }
	live := stsSessionRef(t, "AROAREADER:live-lease", now.Add(time.Hour))
	if _, err := off.RevokeMethod(context.Background(), live); !errors.Is(err, ErrAWSSTSSessionActive) {
		t.Fatalf("opted-out early revoke = %v", err)
	}
	off.query.now = func() time.Time { return now.Add(time.Hour + time.Second) }
	if method, err := off.RevokeMethod(context.Background(), live); err != nil || method != RevocationMethodNativeExpiry {
		t.Fatalf("opted-out revoke after expiry = %q %v", method, err)
	}
	if len(plain.actions) != 0 {
		t.Fatalf("an opted-out provider called IAM: %v", plain.actions)
	}
}

func TestAWSSTSDenyPolicyNameRoundTripsItsExpiryN3(t *testing.T) {
	expiration := time.Date(2026, 11, 4, 9, 30, 0, 0, time.UTC)
	name := AWSSTSDenyPolicyName("AROAREADER:trstctl-reader-lease", expiration)
	if got, ok := awsSTSDenyPolicyExpiry(name); !ok || !got.Equal(expiration) {
		t.Fatalf("expiry of %s = %v %v", name, got, ok)
	}
	for _, other := range []string{"app-inline", "trstctl-revoked-", "trstctl-revoked-x-0123456789ab", "trstctl-revoked-100-short", "trstctl-revoked--1-0123456789ab"} {
		if _, ok := awsSTSDenyPolicyExpiry(other); ok {
			t.Fatalf("%q read as a denial", other)
		}
	}
}
