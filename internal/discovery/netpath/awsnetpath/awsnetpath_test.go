// SPDX-License-Identifier: BUSL-1.1

package awsnetpath_test

import (
	"context"
	"net/netip"
	"testing"

	"trstctl.com/trstctl/internal/discovery/netpath"
	"trstctl.com/trstctl/internal/discovery/netpath/awsnetpath"
	"trstctl.com/trstctl/internal/discovery/netpath/awsnetpath/ec2test"
)

const (
	testAccessKey = "AKIAA167EXAMPLE"
	testSecretKey = "a167-test-secret-key" // #nosec G101 -- fabricated fixture credential (CWE-798)
)

// SeedA167 builds one VPC with a public subnet (internet gateway route) and a
// private one (NAT only), one shared network ACL that admits 443, and three
// interfaces: a web host open on 443, an admin host whose group admits only a
// partner range, and a host in the private subnet.
func SeedA167(s *ec2test.Server) {
	s.Seed(
		[]ec2test.Interface{
			{ID: "eni-web", SubnetID: "subnet-public", VPCID: "vpc-1", PublicIP: "203.0.113.10", Groups: []string{"sg-web"}},
			{ID: "eni-admin", SubnetID: "subnet-public", VPCID: "vpc-1", PublicIP: "203.0.113.11", Groups: []string{"sg-admin"}},
			{ID: "eni-private", SubnetID: "subnet-private", VPCID: "vpc-1", PublicIP: "203.0.113.12", Groups: []string{"sg-web"}},
		},
		[]ec2test.SecurityGroup{
			{ID: "sg-web", Inbound: []ec2test.Permission{{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRs: []string{"0.0.0.0/0"}}}},
			{ID: "sg-admin", Inbound: []ec2test.Permission{{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRs: []string{"198.51.100.0/24"}}}},
		},
		[]ec2test.RouteTable{
			{ID: "rtb-main", VPCID: "vpc-1", Main: true, Routes: []ec2test.Route{{Destination: "10.0.0.0/16", Target: "local"}, {Destination: "0.0.0.0/0", Target: "nat-1"}}},
			{ID: "rtb-public", VPCID: "vpc-1", Subnets: []string{"subnet-public"}, Routes: []ec2test.Route{{Destination: "10.0.0.0/16", Target: "local"}, {Destination: "0.0.0.0/0", Target: "igw-1"}}},
		},
		[]ec2test.NetworkACL{{ID: "acl-1", Subnets: []string{"subnet-public", "subnet-private"}, Entries: []ec2test.ACLEntry{
			{Number: 100, Allow: true, Protocol: "6", CIDR: "0.0.0.0/0", FromPort: 443, ToPort: 443},
			{Number: 32767, Protocol: "-1", CIDR: "0.0.0.0/0"},
			{Number: 100, Egress: true, Allow: true, Protocol: "6", CIDR: "0.0.0.0/0", FromPort: 1024, ToPort: 65535},
			{Number: 32767, Egress: true, Protocol: "-1", CIDR: "0.0.0.0/0"},
		}}},
	)
}

// A167: the reader asks EC2, signed and read-only, for exactly the resources
// on the path to one public address, and the evaluator names what decides.
func TestReaderFeedsTheEvaluatorFromSignedDescribeCalls(t *testing.T) {
	stand := ec2test.New(testAccessKey, testSecretKey)
	t.Cleanup(stand.Close)
	SeedA167(stand)
	reader, err := awsnetpath.New(awsnetpath.Config{Region: "us-east-1", Endpoint: stand.URL(), AccessKeyID: testAccessKey,
		SecretAccessKey: testSecretKey, HTTPClient: stand.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	verdict := func(ip string) netpath.Result {
		t.Helper()
		cfg, found, err := reader.Path(ctx, netip.MustParseAddr(ip))
		if err != nil {
			t.Fatalf("read path to %s: %v", ip, err)
		}
		if !found {
			return netpath.Result{Verdict: netpath.NotInAccount}
		}
		return netpath.Evaluate(netip.MustParseAddr(ip), 443, cfg)
	}
	if got := verdict("203.0.113.10"); got.Verdict != netpath.Open || got.Resource != "sg-web" {
		t.Fatalf("web host = %+v, want open through sg-web", got)
	}
	if got := verdict("203.0.113.11"); got.Verdict != netpath.Blocked || got.BlockedBy != netpath.StageSecurityGroup || got.Resource != "sg-admin" {
		t.Fatalf("admin host = %+v, want blocked by sg-admin", got)
	}
	if got := verdict("203.0.113.12"); got.Verdict != netpath.Blocked || got.BlockedBy != netpath.StageRoute || got.Resource != "rtb-main" {
		t.Fatalf("private host = %+v, want blocked by the main route table", got)
	}
	if got := verdict("192.0.2.99"); got.Verdict != netpath.NotInAccount {
		t.Fatalf("foreign address = %+v, want not_in_account", got)
	}
	if stand.NonDescribeCalls() != 0 || stand.Refused() != 0 {
		t.Fatalf("non-describe calls %d, refused signatures %d", stand.NonDescribeCalls(), stand.Refused())
	}
	wrong, err := awsnetpath.New(awsnetpath.Config{Region: "us-east-1", Endpoint: stand.URL(), AccessKeyID: testAccessKey,
		SecretAccessKey: "wrong", HTTPClient: stand.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := wrong.Path(ctx, netip.MustParseAddr("203.0.113.10")); err == nil || stand.Refused() != 1 {
		t.Fatalf("a wrong secret = %v refused %d; want the signature refused", err, stand.Refused())
	}
}
