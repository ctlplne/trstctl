// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// iamQuotaDouble answers IAM's role-policy and managed-policy calls the way
// IAM does for one role (written from IAM's API reference): the role holds at
// most inlineQuota inline policies, past which PutRolePolicy is LimitExceeded;
// managed policies live under their ARN, attach to the role, and can't be
// deleted while attached.
type iamQuotaDouble struct {
	mu          sync.Mutex
	role        string
	inlineQuota int
	inline      map[string]string
	managed     map[string]string
	attached    map[string]bool
	actions     []string
}

func (d *iamQuotaDouble) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	action := r.Form.Get("Action")
	d.actions = append(d.actions, action)
	if !strings.Contains(r.Header.Get("Authorization"), "/iam/aws4_request") {
		http.Error(w, "<Error><Code>InvalidClientTokenId</Code></Error>", http.StatusForbidden)
		return
	}
	fail := func(status int, code string) {
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, "<ErrorResponse><Error><Code>%s</Code></Error></ErrorResponse>", code) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
	}
	if role := r.Form.Get("RoleName"); role != "" && role != d.role {
		fail(http.StatusNotFound, "NoSuchEntity")
		return
	}
	name, arn := r.Form.Get("PolicyName"), r.Form.Get("PolicyArn")
	switch action {
	case "PutRolePolicy":
		if _, exists := d.inline[name]; !exists && len(d.inline) >= d.inlineQuota {
			fail(http.StatusConflict, "LimitExceeded")
			return
		}
		d.inline[name] = r.Form.Get("PolicyDocument")
		_, _ = fmt.Fprint(w, `<PutRolePolicyResponse/>`)
	case "GetRolePolicy":
		doc, ok := d.inline[name]
		if !ok {
			fail(http.StatusNotFound, "NoSuchEntity")
			return
		}
		_, _ = fmt.Fprintf(w, `<GetRolePolicyResponse><GetRolePolicyResult><PolicyDocument>%s</PolicyDocument></GetRolePolicyResult></GetRolePolicyResponse>`, url.PathEscape(doc)) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
	case "ListRolePolicies":
		var names []string
		for n := range d.inline {
			names = append(names, n)
		}
		sort.Strings(names)
		_, _ = fmt.Fprintf(w, `<ListRolePoliciesResponse><ListRolePoliciesResult><PolicyNames><member>%s</member></PolicyNames><IsTruncated>false</IsTruncated></ListRolePoliciesResult></ListRolePoliciesResponse>`, strings.Join(names, "</member><member>")) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
	case "DeleteRolePolicy":
		if _, ok := d.inline[name]; !ok {
			fail(http.StatusNotFound, "NoSuchEntity")
			return
		}
		delete(d.inline, name)
		_, _ = fmt.Fprint(w, `<DeleteRolePolicyResponse/>`)
	case "CreatePolicy":
		arn := "arn:aws:iam::123456789012:policy" + r.Form.Get("Path") + name
		if _, ok := d.managed[arn]; ok {
			fail(http.StatusConflict, "EntityAlreadyExists")
			return
		}
		d.managed[arn] = r.Form.Get("PolicyDocument")
		_, _ = fmt.Fprintf(w, `<CreatePolicyResponse><CreatePolicyResult><Policy><Arn>%s</Arn><DefaultVersionId>v1</DefaultVersionId></Policy></CreatePolicyResult></CreatePolicyResponse>`, arn) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
	case "AttachRolePolicy":
		if _, ok := d.managed[arn]; !ok {
			fail(http.StatusNotFound, "NoSuchEntity")
			return
		}
		d.attached[arn] = true
		_, _ = fmt.Fprint(w, `<AttachRolePolicyResponse/>`)
	case "ListAttachedRolePolicies":
		var b strings.Builder
		for a := range d.attached {
			if strings.Contains(a, ":policy"+r.Form.Get("PathPrefix")) {
				b.WriteString("<member><PolicyName>" + a[strings.LastIndex(a, "/")+1:] + "</PolicyName><PolicyArn>" + a + "</PolicyArn></member>")
			}
		}
		_, _ = fmt.Fprintf(w, `<ListAttachedRolePoliciesResponse><ListAttachedRolePoliciesResult><AttachedPolicies>%s</AttachedPolicies><IsTruncated>false</IsTruncated></ListAttachedRolePoliciesResult></ListAttachedRolePoliciesResponse>`, b.String()) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
	case "GetPolicy":
		if _, ok := d.managed[arn]; !ok {
			fail(http.StatusNotFound, "NoSuchEntity")
			return
		}
		_, _ = fmt.Fprint(w, `<GetPolicyResponse><GetPolicyResult><Policy><DefaultVersionId>v1</DefaultVersionId></Policy></GetPolicyResult></GetPolicyResponse>`)
	case "GetPolicyVersion":
		doc, ok := d.managed[arn]
		if !ok || r.Form.Get("VersionId") != "v1" {
			fail(http.StatusNotFound, "NoSuchEntity")
			return
		}
		_, _ = fmt.Fprintf(w, `<GetPolicyVersionResponse><GetPolicyVersionResult><PolicyVersion><Document>%s</Document></PolicyVersion></GetPolicyVersionResult></GetPolicyVersionResponse>`, url.PathEscape(doc)) // #nosec G705 -- test writes fixture bytes to its own local server (CWE-79)
	case "DetachRolePolicy":
		delete(d.attached, arn)
		_, _ = fmt.Fprint(w, `<DetachRolePolicyResponse/>`)
	case "DeletePolicy":
		if d.attached[arn] {
			fail(http.StatusConflict, "DeleteConflict")
			return
		}
		delete(d.managed, arn)
		_, _ = fmt.Fprint(w, `<DeletePolicyResponse/>`)
	default:
		fail(http.StatusBadRequest, "InvalidAction")
	}
}

func (d *iamQuotaDouble) snapshot() (inline []string, managed map[string]string, attached []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for n := range d.inline {
		inline = append(inline, n)
	}
	sort.Strings(inline)
	managed = map[string]string{}
	for k, v := range d.managed {
		managed[k] = v
	}
	for a := range d.attached {
		attached = append(attached, a)
	}
	sort.Strings(attached)
	return inline, managed, attached
}

// N3-L2: when the role's inline policies are at IAM's quota, a provider with
// the fallback attaches a managed policy denying every session of the role
// issued before now instead of failing; the revocation still completes as
// deny_policy only after the attachment and the document are read back. The
// cutoff covers the per-session denials of sessions issued before it, which
// are deleted to free the quota, while denials it can't prove covered and the
// role's own policies stay. A later fallback attaches a later cutoff and
// removes the earlier one. Without the fallback the quota still fails the
// revocation, and the fallback needs revoke_with_deny_policy.
func TestAWSSTSDenyBeforeCutoffWhenTheQuotaIsFullN3L2(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	newBackend := func(d *iamQuotaDouble, fallback bool) *AWSSTSBackend {
		t.Helper()
		server := httptest.NewServer(d)
		t.Cleanup(server.Close)
		b, err := NewAWSSTSBackend(AWSSTSConfig{
			Endpoint: server.URL, HTTPClient: server.Client(), Region: "us-east-1",
			AccessKeyID: "AKIDN3L2", SecretAccessKey: []byte("n3l2-signing-value"),
			RoleARNs:    map[string]string{"reader": "arn:aws:iam::123456789012:role/trstctl-reader"},
			IAMEndpoint: server.URL, RevokeWithDenyPolicy: true, DenyBeforeCutoffWhenFull: fallback,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(b.Close)
		b.query.now = func() time.Time { return now }
		return b
	}
	double := func() *iamQuotaDouble {
		return &iamQuotaDouble{role: "trstctl-reader", inlineQuota: 2, managed: map[string]string{}, attached: map[string]bool{},
			inline: map[string]string{"app-inline": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`}}
	}

	d := double()
	b := newBackend(d, true)
	shortLived := "AROAREADER:short-lived"
	if method, err := b.RevokeMethod(context.Background(), stsSessionRef(t, shortLived, now.Add(10*time.Minute))); err != nil || method != RevocationMethodDenyPolicy {
		t.Fatalf("the first revocation = %q %v; want its own inline denial", method, err)
	}
	if method, err := b.RevokeMethod(context.Background(), stsSessionRef(t, "AROAREADER:long-lived", now.Add(time.Hour))); err != nil || method != RevocationMethodDenyPolicy {
		t.Fatalf("the revocation past the quota = %q %v; want the cutoff fallback", method, err)
	}
	inline, managed, attached := d.snapshot()
	cutoff := now.Add(time.Second)
	if len(attached) != 1 || !awsSTSCutoffHolds(managed[attached[0]], cutoff) || !strings.Contains(attached[0], ":policy/trstctl/"+awsSTSCutoffPolicyName("trstctl-reader", cutoff)) {
		t.Fatalf("attached %v managed %v; want one cutoff policy at %s", attached, managed, cutoff)
	}
	if strings.Join(inline, ",") != "app-inline" {
		t.Fatalf("inline policies after the fallback = %v; want the covered denial deleted and the role's own policy kept", inline)
	}

	// Two hours on the quota is full again: a later cutoff replaces the first.
	d.mu.Lock()
	d.inline["trstctl-revoked-"+fmt.Sprint(now.Add(5*time.Hour).Unix())+"-aaaaaaaaaaaa"] = `{"Version":"2012-10-17","Statement":[]}`
	d.mu.Unlock()
	later := now.Add(2 * time.Hour)
	b.query.now = func() time.Time { return later }
	if method, err := b.RevokeMethod(context.Background(), stsSessionRef(t, "AROAREADER:another", later.Add(time.Hour))); err != nil || method != RevocationMethodDenyPolicy {
		t.Fatalf("the later revocation = %q %v", method, err)
	}
	inline, managed, attached = d.snapshot()
	if len(attached) != 1 || len(managed) != 1 || !awsSTSCutoffHolds(managed[attached[0]], later.Add(time.Second)) {
		t.Fatalf("after the later cutoff: attached %v managed %v; want only the later cutoff", attached, managed)
	}
	if len(inline) != 2 {
		t.Fatalf("inline policies = %v; want the role's own and the denial the cutoff can't prove covered", inline)
	}

	full := double()
	// A live session's denial (expiring in five hours) fills the quota; pruning
	// removes only expired denials, so it stays full.
	full.inline["trstctl-revoked-"+fmt.Sprint(now.Add(5*time.Hour).Unix())+"-bbbbbbbbbbbb"] = `{}`
	strict := newBackend(full, false)
	if _, err := strict.RevokeMethod(context.Background(), stsSessionRef(t, "AROAREADER:no-fallback", now.Add(time.Hour))); !errors.Is(err, errAWSIAMLimitExceeded) {
		t.Fatalf("without the fallback the quota = %v; want the limit as the revocation's error", err)
	}
	if _, managed, _ := full.snapshot(); len(managed) != 0 {
		t.Fatalf("a provider without the fallback created %v", managed)
	}
	if _, err := NewAWSSTSBackend(AWSSTSConfig{Endpoint: "https://sts.us-east-1.amazonaws.com", Region: "us-east-1",
		AccessKeyID: "AKIDN3L2", SecretAccessKey: []byte("n3l2-signing-value"),
		RoleARNs: map[string]string{"reader": "arn:aws:iam::123456789012:role/trstctl-reader"}, DenyBeforeCutoffWhenFull: true,
	}); err == nil || !strings.Contains(err.Error(), "needs revoke_with_deny_policy") {
		t.Fatalf("the fallback without revoke_with_deny_policy = %v", err)
	}
	for name, doc := range map[string]string{
		"an allow":          `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"` + cutoff.Format(time.RFC3339) + `"}}}]}`,
		"another time":      `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"2020-01-01T00:00:00Z"}}}]}`,
		"a narrower act":    `{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"` + cutoff.Format(time.RFC3339) + `"}}}]}`,
		"after, not before": `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateGreaterThan":{"aws:TokenIssueTime":"` + cutoff.Format(time.RFC3339) + `"}}}]}`,
	} {
		if awsSTSCutoffHolds(doc, cutoff) {
			t.Fatalf("%s read back as the cutoff", name)
		}
	}
}
