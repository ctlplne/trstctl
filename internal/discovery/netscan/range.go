package netscan

import (
	"errors"
	"fmt"
	"net"
	"strconv"
)

// maxRangeHosts caps how many addresses ExpandRange will enumerate, guarding
// against an operator accidentally expanding a huge range (for example an IPv4
// /8, or any IPv6 prefix) into a memory bomb. Concurrency during the scan is
// bounded separately by the worker pool.
const maxRangeHosts = 1 << 16

// ExpandRange enumerates every address in a CIDR crossed with the given ports as
// "host:port" targets, in order. It rejects an empty port list and a range whose
// host count exceeds maxRangeHosts.
func ExpandRange(cidr string, ports []int) ([]string, error) {
	if len(ports) == 0 {
		return nil, errors.New("netscan: at least one port is required")
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("netscan: parse CIDR %q: %w", cidr, err)
	}
	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	if hostBits >= 17 || (1<<uint(hostBits)) > maxRangeHosts {
		return nil, fmt.Errorf("netscan: range %s has too many addresses (max %d)", cidr, maxRangeHosts)
	}

	var targets []string
	for ip := cloneIP(ipnet.IP); ipnet.Contains(ip); incIP(ip) {
		host := ip.String()
		for _, p := range ports {
			targets = append(targets, net.JoinHostPort(host, strconv.Itoa(p)))
		}
	}
	return targets, nil
}

func cloneIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

// incIP increments an IP address in place (big-endian), so iteration walks the
// range one address at a time.
func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}
