// SPDX-License-Identifier: BUSL-1.1

package awsnetpath_test

import (
	"context"
	"net/netip"
	"strings"
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

// SeedA167L2 adds, beside SeedA167's VPC, the addresses A167-L2 follows (load
// balancers and the NAT gateway in a subnet whose network ACL admits all): an
// application load balancer (three listeners, one a page), a network load
// balancer without security groups, a classic load balancer, a NAT gateway,
// a host whose subnet replies through a transit gateway, a host whose inbound
// traffic the internet gateway's own route table steers through an
// inspection endpoint, and a host's own interface whose description merely
// looks like a load balancer's.
func SeedA167L2(s *ec2test.Server) {
	s.Seed(
		[]ec2test.Interface{
			{ID: "eni-alb", SubnetID: "subnet-lb", VPCID: "vpc-1", PublicIP: "203.0.113.20", Groups: []string{"sg-alb"},
				RequesterManaged: true, Description: "ELB app/web/50dc6c495c0c9188", PrivateIP: "10.0.1.20"},
			{ID: "eni-nlb", SubnetID: "subnet-lb", VPCID: "vpc-1", PublicIP: "203.0.113.21", Type: "network_load_balancer",
				RequesterManaged: true, Description: "ELB net/edge/7f3c2b1a", PrivateIP: "10.0.1.21"},
			{ID: "eni-clb", SubnetID: "subnet-lb", VPCID: "vpc-1", PublicIP: "203.0.113.22", Groups: []string{"sg-alb"},
				RequesterManaged: true, Description: "ELB legacy", PrivateIP: "10.0.1.22"},
			{ID: "eni-nat", SubnetID: "subnet-lb", VPCID: "vpc-1", PublicIP: "203.0.113.23", Type: "nat_gateway",
				RequesterManaged: true, Description: "Interface for NAT Gateway nat-0a1b2c3d", PrivateIP: "10.0.1.23"},
			{ID: "eni-hub", SubnetID: "subnet-hub", VPCID: "vpc-1", PublicIP: "203.0.113.24", Groups: []string{"sg-web"}, PrivateIP: "10.0.2.24"},
			{ID: "eni-inspected", SubnetID: "subnet-inspected", VPCID: "vpc-1", PublicIP: "203.0.113.25", Groups: []string{"sg-web"}, PrivateIP: "10.0.3.25"},
			{ID: "eni-lookalike", SubnetID: "subnet-lb", VPCID: "vpc-1", PublicIP: "203.0.113.26", Groups: []string{"sg-web"},
				Description: "ELB app/web/50dc6c495c0c9188", PrivateIP: "10.0.1.26"},
		},
		[]ec2test.SecurityGroup{
			{ID: "sg-alb", Inbound: []ec2test.Permission{{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRs: []string{"0.0.0.0/0"}},
				{Protocol: "tcp", FromPort: 8443, ToPort: 8443, CIDRs: []string{"0.0.0.0/0"}}}},
		},
		[]ec2test.RouteTable{
			{ID: "rtb-lb", VPCID: "vpc-1", Subnets: []string{"subnet-lb"}, Routes: []ec2test.Route{{Destination: "10.0.0.0/16", Target: "local"}, {Destination: "0.0.0.0/0", Target: "igw-1"}}},
			{ID: "rtb-hub", VPCID: "vpc-1", Subnets: []string{"subnet-hub"}, Routes: []ec2test.Route{{Destination: "10.0.0.0/16", Target: "local"}, {Destination: "0.0.0.0/0", Target: "tgw-1"}}},
			{ID: "rtb-inspected", VPCID: "vpc-1", Subnets: []string{"subnet-inspected"}, Routes: []ec2test.Route{{Destination: "10.0.0.0/16", Target: "local"}, {Destination: "0.0.0.0/0", Target: "igw-1"}}},
			{ID: "rtb-edge", VPCID: "vpc-1", Gateways: []string{"igw-1"}, Routes: []ec2test.Route{{Destination: "10.0.0.0/16", Target: "local"}, {Destination: "10.0.3.0/24", Target: "vpce-0abc"}}},
		},
		[]ec2test.NetworkACL{{ID: "acl-2", Subnets: []string{"subnet-lb", "subnet-hub", "subnet-inspected"}, Entries: []ec2test.ACLEntry{
			{Number: 100, Allow: true, Protocol: "-1", CIDR: "0.0.0.0/0"},
			{Number: 100, Egress: true, Allow: true, Protocol: "-1", CIDR: "0.0.0.0/0"},
		}}},
	)
	s.SeedLoadBalancers(
		ec2test.LoadBalancer{ARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/50dc6c495c0c9188", Name: "web",
			Type: "application", Scheme: "internet-facing", SecurityGroups: []string{"sg-alb"},
			Listeners: []ec2test.Listener{{Port: 80, Protocol: "HTTP"}, {Port: 8080, Protocol: "HTTP"}, {Port: 443, Protocol: "HTTPS"}}},
		ec2test.LoadBalancer{ARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/edge/7f3c2b1a", Name: "edge",
			Type: "network", Scheme: "internet-facing", Listeners: []ec2test.Listener{{Port: 443, Protocol: "TLS"}}},
		ec2test.LoadBalancer{Name: "legacy", Type: "classic", Scheme: "internet-facing", SecurityGroups: []string{"sg-alb"},
			Listeners: []ec2test.Listener{{Port: 443, Protocol: "SSL"}}},
	)
}

// A167-L2: the reader names what holds the address and reads the rest of the
// path from it — a load balancer's listeners (every page) and its own groups
// from Elastic Load Balancing, signed for that service; a NAT gateway; the
// transit gateway a subnet replies through; the internet gateway's own route
// table — and the evaluator decides.
func TestReaderFollowsLoadBalancersNATAndGatewayRoutesA167L2(t *testing.T) {
	stand := ec2test.New(testAccessKey, testSecretKey)
	t.Cleanup(stand.Close)
	SeedA167(stand)
	SeedA167L2(stand)
	reader, err := awsnetpath.New(awsnetpath.Config{Region: "us-east-1", Endpoint: stand.URL(), AccessKeyID: testAccessKey,
		SecretAccessKey: testSecretKey, HTTPClient: stand.Client(), ELBEndpoint: stand.URL()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	judge := func(ip string, port int) netpath.Result {
		t.Helper()
		cfg, found, err := reader.Path(ctx, netip.MustParseAddr(ip))
		if err != nil || !found {
			t.Fatalf("read path to %s: found %v, %v", ip, found, err)
		}
		return netpath.Evaluate(netip.MustParseAddr(ip), port, cfg)
	}
	if got := judge("203.0.113.20", 443); got.Verdict != netpath.Open || got.Resource != "sg-alb" ||
		strings.Join(got.Path, ">") != "eni-alb>app/web/50dc6c495c0c9188>sg-alb>acl-2>rtb-lb>igw-1" {
		t.Fatalf("application load balancer on 443 = %+v", got)
	}
	if n := stand.Calls("elbv2:DescribeListeners"); n != 3 {
		t.Fatalf("listener pages read = %d, want 3 (one listener a page)", n)
	}
	if got := judge("203.0.113.20", 8443); got.Verdict != netpath.Blocked || got.BlockedBy != netpath.StageListener ||
		got.Resource != "app/web/50dc6c495c0c9188" || !strings.Contains(got.Reason, "tcp/80, tcp/443, tcp/8080") {
		t.Fatalf("application load balancer on 8443 = %+v", got)
	}
	if got := judge("203.0.113.21", 443); got.Verdict != netpath.Open || got.Resource != "net/edge/7f3c2b1a" ||
		strings.Join(got.Path, ">") != "eni-nlb>net/edge/7f3c2b1a>acl-2>rtb-lb>igw-1" {
		t.Fatalf("network load balancer without groups = %+v", got)
	}
	if got := judge("203.0.113.22", 443); got.Verdict != netpath.Open || got.Resource != "sg-alb" || got.Path[1] != "legacy" {
		t.Fatalf("classic load balancer = %+v", got)
	}
	if n := stand.Calls("elb:DescribeLoadBalancers"); n != 1 {
		t.Fatalf("classic lookups = %d", n)
	}
	if got := judge("203.0.113.23", 443); got.Verdict != netpath.Blocked || got.BlockedBy != netpath.StageNATGateway || got.Resource != "nat-0a1b2c3d" {
		t.Fatalf("NAT gateway = %+v", got)
	}
	if got := judge("203.0.113.24", 443); got.Verdict != netpath.Unknown || got.Resource != "tgw-1" || !strings.Contains(got.Reason, "transit gateway tgw-1") {
		t.Fatalf("host replying through a transit gateway = %+v", got)
	}
	if got := judge("203.0.113.25", 443); got.Verdict != netpath.Unknown || got.Resource != "vpce-0abc" ||
		strings.Join(got.Path, ">") != "eni-inspected>sg-web>acl-2>rtb-inspected>vpce-0abc>igw-1" {
		t.Fatalf("host behind an inspection endpoint = %+v", got)
	}
	lookups := stand.Calls("elbv2:DescribeLoadBalancers")
	if got := judge("203.0.113.26", 443); got.Verdict != netpath.Open || got.Resource != "sg-web" || got.Path[1] != "sg-web" ||
		stand.Calls("elbv2:DescribeLoadBalancers") != lookups {
		t.Fatalf("a host's own interface described like a load balancer's = %+v (lookups %d → %d)", got, lookups, stand.Calls("elbv2:DescribeLoadBalancers"))
	}
	if stand.NonDescribeCalls() != 0 || stand.Refused() != 0 {
		t.Fatalf("non-describe calls %d, refused signatures %d", stand.NonDescribeCalls(), stand.Refused())
	}
}

// A167-L5: IPv6 addresses against the stand-in — found by the interface's
// IPv6 address, judged by the IPv6 entries EC2 reports in ipv6CidrBlock and
// ipv6Ranges, routed by the IPv6 route that holds global unicast, and, on a
// dual-stack load balancer, by its listeners as over IPv4.
func TestReaderJudgesIPv6PathsA167L5(t *testing.T) {
	stand := ec2test.New(testAccessKey, testSecretKey)
	t.Cleanup(stand.Close)
	SeedA167(stand)
	stand.Seed(
		[]ec2test.Interface{
			{ID: "eni-v6", SubnetID: "subnet-v6", VPCID: "vpc-1", IPv6: "2001:db8:1200::10", Groups: []string{"sg-v6"}, PrivateIP: "10.0.6.10"},
			{ID: "eni-v6-legacy", SubnetID: "subnet-v6", VPCID: "vpc-1", IPv6: "2001:db8:1200::11", Groups: []string{"sg-web"}, PrivateIP: "10.0.6.11"},
			{ID: "eni-v6-private", SubnetID: "subnet-v6-private", VPCID: "vpc-1", IPv6: "2001:db8:1201::10", Groups: []string{"sg-v6"}, PrivateIP: "10.0.7.10"},
			{ID: "eni-v6-alb", SubnetID: "subnet-v6", VPCID: "vpc-1", IPv6: "2001:db8:1200::20", Groups: []string{"sg-v6"},
				RequesterManaged: true, Description: "ELB app/dual/9e8d7c6b5a4f3e2d", PrivateIP: "10.0.6.20"},
		},
		[]ec2test.SecurityGroup{
			{ID: "sg-v6", Inbound: []ec2test.Permission{{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRs: []string{"0.0.0.0/0", "2000::/3"}}}},
		},
		[]ec2test.RouteTable{
			{ID: "rtb-v6", VPCID: "vpc-1", Subnets: []string{"subnet-v6"}, Routes: []ec2test.Route{
				{Destination: "10.0.0.0/16", Target: "local"}, {Destination: "2001:db8:1200::/56", Target: "local"},
				{Destination: "0.0.0.0/0", Target: "igw-1"}, {Destination: "::/0", Target: "igw-1"}}},
			{ID: "rtb-v6-private", VPCID: "vpc-1", Subnets: []string{"subnet-v6-private"}, Routes: []ec2test.Route{
				{Destination: "10.0.0.0/16", Target: "local"}, {Destination: "::/0", Target: "eigw-1"}}},
		},
		[]ec2test.NetworkACL{{ID: "acl-v6", Subnets: []string{"subnet-v6", "subnet-v6-private"}, Entries: []ec2test.ACLEntry{
			{Number: 100, Allow: true, Protocol: "6", CIDR: "0.0.0.0/0", FromPort: 443, ToPort: 443},
			{Number: 101, Allow: true, Protocol: "6", CIDR: "::/0", FromPort: 443, ToPort: 443},
			{Number: 32767, Protocol: "-1", CIDR: "0.0.0.0/0"},
			{Number: 32768, Protocol: "-1", CIDR: "::/0"},
			{Number: 100, Egress: true, Allow: true, Protocol: "-1", CIDR: "0.0.0.0/0"},
			{Number: 101, Egress: true, Allow: true, Protocol: "-1", CIDR: "::/0"},
		}}},
	)
	stand.SeedLoadBalancers(ec2test.LoadBalancer{ARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/dual/9e8d7c6b5a4f3e2d",
		Name: "dual", Type: "application", Scheme: "internet-facing", SecurityGroups: []string{"sg-v6"},
		Listeners: []ec2test.Listener{{Port: 443, Protocol: "HTTPS"}}})
	reader, err := awsnetpath.New(awsnetpath.Config{Region: "us-east-1", Endpoint: stand.URL(), AccessKeyID: testAccessKey,
		SecretAccessKey: testSecretKey, HTTPClient: stand.Client(), ELBEndpoint: stand.URL()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	judge := func(ip string, port int) netpath.Result {
		t.Helper()
		addr := netip.MustParseAddr(ip)
		cfg, found, err := reader.Path(ctx, addr)
		if err != nil {
			t.Fatalf("read path to %s: %v", ip, err)
		}
		if !found {
			return netpath.Result{Verdict: netpath.NotInAccount}
		}
		return netpath.Evaluate(addr, port, cfg)
	}
	if got := judge("2001:db8:1200::10", 443); got.Verdict != netpath.Open || strings.Join(got.Path, ">") != "eni-v6>sg-v6>acl-v6>rtb-v6>igw-1" ||
		!strings.Contains(got.Reason, "from 2000::/3") {
		t.Fatalf("IPv6 host = %+v", got)
	}
	if got := judge("2001:db8:1200::11", 443); got.Verdict != netpath.Blocked || got.BlockedBy != netpath.StageSecurityGroup || got.Resource != "sg-web" {
		t.Fatalf("IPv6 host whose group admits IPv4 only = %+v", got)
	}
	if got := judge("2001:db8:1201::10", 443); got.Verdict != netpath.Blocked || got.BlockedBy != netpath.StageRoute || got.Resource != "rtb-v6-private" ||
		!strings.Contains(got.Reason, "eigw-1") {
		t.Fatalf("IPv6 host behind an egress-only gateway = %+v", got)
	}
	if got := judge("2001:db8:1200::20", 443); got.Verdict != netpath.Open || got.Path[1] != "app/dual/9e8d7c6b5a4f3e2d" {
		t.Fatalf("dual-stack load balancer over IPv6 = %+v", got)
	}
	if got := judge("2001:db8:1200::99", 443); got.Verdict != netpath.NotInAccount {
		t.Fatalf("an IPv6 address no interface holds = %+v", got)
	}
	if got := judge("::ffff:203.0.113.10", 443); got.Verdict != netpath.Open || got.Resource != "sg-web" {
		t.Fatalf("an IPv4-mapped address is looked up as IPv4: %+v", got)
	}
	if stand.NonDescribeCalls() != 0 || stand.Refused() != 0 {
		t.Fatalf("non-describe calls %d, refused signatures %d", stand.NonDescribeCalls(), stand.Refused())
	}
}
