// SPDX-License-Identifier: BUSL-1.1

package netsec

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"

	"trstctl.com/trstctl/internal/crypto/dbdsn"
)

const databaseDialTimeout = 10 * time.Second

// DatabaseDialOptions combines the operator policy that owns a configured DSN
// with the local policy of a gateway, when this runs in a gateway process.
type DatabaseDialOptions struct {
	OperatorFile bool
	PrivateCIDRs []netip.Prefix
	Agent        *RelayEgress
	CheckName    func(string) error
}

// DatabaseDialer isolates DNS admission from the check on the actual peer. A
// driver that resolves its own name must use LookupHost and DialResolved.
type DatabaseDialer struct{ policy DatabaseDialOptions }

func NewDatabaseDialer(policy DatabaseDialOptions) DatabaseDialer {
	return DatabaseDialer{policy: policy}
}

// ForDiscoveredPeer removes the implicit private-network allowance of an
// operator's explicit file DSN. Discovered private peers require a CIDR grant.
func (d DatabaseDialer) ForDiscoveredPeer() DatabaseDialer {
	d.policy.OperatorFile = false
	return d
}

func (d DatabaseDialer) CheckHost(host string) error {
	name, err := dbdsn.HostName(host)
	if err != nil {
		return ErrSSRFBlocked
	}
	if d.policy.CheckName != nil {
		return d.policy.CheckName(name)
	}
	return nil
}

// CheckEndpoint rejects an already-literal destination before opening a
// connection. Names still need the actual socket's resolved-IP check.
func (d DatabaseDialer) CheckEndpoint(endpoint string) error {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return ErrSSRFBlocked
	}
	if err := d.CheckHost(host); err != nil {
		return err
	}
	if _, err := netip.ParseAddrPort(endpoint); err == nil {
		return d.control("tcp", endpoint, nil)
	}
	return nil
}

func (d DatabaseDialer) LookupHost(ctx context.Context, host string) ([]string, error) {
	if err := d.CheckHost(host); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, databaseDialTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 || len(ips) > dbdsn.MaxHosts {
		return nil, ErrSSRFBlocked
	}
	addresses := make([]string, len(ips))
	for i, ip := range ips {
		addresses[i] = ip.Unmap().String()
	}
	return addresses, nil
}

func (d DatabaseDialer) DialContext(ctx context.Context, network, endpoint string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || !tcpNetwork(network) {
		return nil, ErrSSRFBlocked
	}
	endpoint, err = dbdsn.TCPAddress(host, port)
	if err != nil {
		return nil, ErrSSRFBlocked
	}
	ctx, cancel := context.WithTimeout(ctx, databaseDialTimeout)
	defer cancel()
	if _, err := netip.ParseAddrPort(endpoint); err == nil {
		if err := d.CheckHost(host); err != nil {
			return nil, err
		}
		return d.DialResolved(ctx, network, endpoint)
	}
	host, port, _ = net.SplitHostPort(endpoint)
	ips, err := d.LookupHost(ctx, host)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, ip := range ips {
		conn, err := d.DialResolved(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

func (d DatabaseDialer) DialResolved(ctx context.Context, network, endpoint string) (net.Conn, error) {
	addr, err := netip.ParseAddrPort(endpoint)
	if err != nil || addr.Port() == 0 || addr.Addr().Zone() != "" || !tcpNetwork(network) {
		return nil, ErrSSRFBlocked
	}
	return d.dial(ctx, network, endpoint)
}

func (d DatabaseDialer) dial(ctx context.Context, network, endpoint string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: databaseDialTimeout, Control: d.control}
	return dialer.DialContext(ctx, network, endpoint)
}

func (d DatabaseDialer) control(network, endpoint string, c syscall.RawConn) error {
	addr, err := netip.ParseAddrPort(endpoint)
	if err != nil || addr.Port() == 0 || addr.Addr().Zone() != "" || !tcpNetwork(network) {
		return ErrSSRFBlocked
	}
	ip := addr.Addr().Unmap()
	if HardBlockedIP(ip.AsSlice()) {
		return ErrSSRFBlocked
	}
	if !d.policy.OperatorFile || !ip.IsLoopback() && !ip.IsPrivate() {
		check := SafeDialControlWithOptions(SafeClientOptions{AllowPrivateCIDRs: d.policy.PrivateCIDRs})
		if err := check(network, endpoint, c); err != nil {
			return err
		}
	}
	return d.policy.Agent.Allow(netip.AddrPortFrom(ip, addr.Port()))
}

func tcpNetwork(network string) bool {
	return network == "tcp" || network == "tcp4" || network == "tcp6"
}
