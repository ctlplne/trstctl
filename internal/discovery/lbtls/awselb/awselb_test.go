// SPDX-License-Identifier: BUSL-1.1

package awselb

import (
	"reflect"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/discovery/lbtls/awselb/elbv2test"
)

func seeded(t *testing.T) *elbv2test.Server {
	t.Helper()
	stand := elbv2test.New("us-west-2", "AKIAX4ELB", "x4-elb-secret")
	t.Cleanup(stand.Close)
	stand.Seed(
		[]elbv2test.LoadBalancer{
			{ARN: "arn:aws:elasticloadbalancing:us-west-2:111122223333:loadbalancer/app/web/1", Name: "web", Type: "application"},
			{ARN: "arn:aws:elasticloadbalancing:us-west-2:111122223333:loadbalancer/net/edge/2", Name: "edge", Type: "network"},
		},
		[]elbv2test.Listener{
			{ARN: "arn:aws:elasticloadbalancing:us-west-2:111122223333:listener/app/web/1/a", LoadBalancerARN: "arn:aws:elasticloadbalancing:us-west-2:111122223333:loadbalancer/app/web/1", Protocol: "HTTPS", Port: 443, SslPolicy: "ELBSecurityPolicy-TLS-1-0-2015-04"},
			{ARN: "arn:aws:elasticloadbalancing:us-west-2:111122223333:listener/app/web/1/b", LoadBalancerARN: "arn:aws:elasticloadbalancing:us-west-2:111122223333:loadbalancer/app/web/1", Protocol: "HTTP", Port: 80},
			{ARN: "arn:aws:elasticloadbalancing:us-west-2:111122223333:listener/net/edge/2/c", LoadBalancerARN: "arn:aws:elasticloadbalancing:us-west-2:111122223333:loadbalancer/net/edge/2", Protocol: "TLS", Port: 8443, SslPolicy: "ELBSecurityPolicy-TLS13-1-2-2021-06"},
		},
		[]elbv2test.Policy{
			{Name: "ELBSecurityPolicy-TLS-1-0-2015-04", Protocols: []string{"TLSv1.2", "TLSv1", "TLSv1.1"}, Ciphers: []string{"ECDHE-RSA-AES128-GCM-SHA256", "AES128-SHA"}},
			{Name: "ELBSecurityPolicy-TLS13-1-2-2021-06", Protocols: []string{"TLSv1.3", "TLSv1.2"}, Ciphers: []string{"TLS_AES_128_GCM_SHA256", "ECDHE-ECDSA-AES128-GCM-SHA256"}},
		},
	)
	return stand
}

// X4: every HTTPS and TLS listener comes back with its security policy's
// versions (oldest first, TLSv1 named TLSv1.0) and ciphers in priority order,
// across paged load balancers and listeners; a plain HTTP listener has no
// policy and is left out; only Describe calls are made, each signed.
func TestListenersReadPolicyVersionsX4(t *testing.T) {
	stand := seeded(t)
	r, err := New(Config{Region: "us-west-2", Endpoint: stand.URL(), AccessKeyID: "AKIAX4ELB", SecretAccessKey: "x4-elb-secret", HTTPClient: stand.Client()}) // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	if err != nil {
		t.Fatal(err)
	}
	ls, err := r.Listeners(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 2 {
		t.Fatalf("listeners = %+v", ls)
	}
	legacy, modern := ls[0], ls[1]
	if !strings.HasSuffix(legacy.Ref, "/app/web/1/a") || legacy.LoadBalancer != "web" || legacy.Port != 443 || legacy.Protocol != "HTTPS" ||
		!reflect.DeepEqual(legacy.Protocols, []string{"TLSv1.0", "TLSv1.1", "TLSv1.2"}) || legacy.Lowest() != "TLSv1.0" || !legacy.Allows("TLSv1.0") ||
		!reflect.DeepEqual(legacy.Ciphers, []string{"ECDHE-RSA-AES128-GCM-SHA256", "AES128-SHA"}) {
		t.Fatalf("legacy listener = %+v", legacy)
	}
	if modern.LoadBalancer != "edge" || modern.Port != 8443 || modern.Protocol != "TLS" || modern.Policy != "ELBSecurityPolicy-TLS13-1-2-2021-06" ||
		!reflect.DeepEqual(modern.Protocols, []string{"TLSv1.2", "TLSv1.3"}) || modern.Allows("TLSv1.0") {
		t.Fatalf("modern listener = %+v", modern)
	}
	if stand.Calls("DescribeLoadBalancers") != 2 || stand.Calls("DescribeListeners") != 3 || stand.Calls("DescribeSSLPolicies") != 1 {
		t.Fatalf("calls: lbs=%d listeners=%d policies=%d", stand.Calls("DescribeLoadBalancers"), stand.Calls("DescribeListeners"), stand.Calls("DescribeSSLPolicies"))
	}
	if stand.NonDescribeCalls() != 0 || stand.Refused() != 0 {
		t.Fatalf("non-describe=%d refused=%d", stand.NonDescribeCalls(), stand.Refused())
	}
}

// A listener whose policy cannot be described fails the read rather than hide
// the weakest policy; a wrong key fails with the error code, never the body.
func TestListenersFailClosedX4(t *testing.T) {
	stand := seeded(t)
	stand.SetPolicy("arn:aws:elasticloadbalancing:us-west-2:111122223333:listener/app/web/1/a", "Custom-Policy-Gone")
	r, _ := New(Config{Region: "us-west-2", Endpoint: stand.URL(), AccessKeyID: "AKIAX4ELB", SecretAccessKey: "x4-elb-secret", HTTPClient: stand.Client()}) // #nosec G101 -- fabricated fixture credential; no value is real (CWE-798)
	if _, err := r.Listeners(t.Context()); err == nil || !strings.Contains(err.Error(), "SSLPolicyNotFound") {
		t.Fatalf("missing policy: err = %v", err)
	}
	wrong, _ := New(Config{Region: "us-west-2", Endpoint: stand.URL(), AccessKeyID: "AKIAX4ELB", SecretAccessKey: "not-the-secret", HTTPClient: stand.Client()})
	if _, err := wrong.Listeners(t.Context()); err == nil || !strings.Contains(err.Error(), "status 403 SignatureDoesNotMatch") {
		t.Fatalf("wrong key: err = %v", err)
	}
}
