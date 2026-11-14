// SPDX-License-Identifier: BUSL-1.1

package migration

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// MaxObservedAddresses bounds how many observed addresses one endpoint names.
const MaxObservedAddresses = 16

// ObservedAddresses reads a deployment target's observed_addresses (X3-L2):
// where an observer sees the endpoint's traffic when NAT or a load balancer
// sits in front of verify_address. Each is host:port with a port from 1 to
// 65535; at most MaxObservedAddresses, no repeats. A target without the key
// has none.
func ObservedAddresses(config json.RawMessage) ([]string, error) {
	var fields struct {
		Observed json.RawMessage `json:"observed_addresses"`
	}
	if len(config) == 0 || json.Unmarshal(config, &fields) != nil || len(fields.Observed) == 0 || string(fields.Observed) == "null" {
		return nil, nil
	}
	var addresses []string
	if err := json.Unmarshal(fields.Observed, &addresses); err != nil {
		return nil, errors.New("observed_addresses must be a list of host:port strings")
	}
	return CleanObservedAddresses(addresses)
}

// CleanObservedAddresses checks a list of observed addresses as
// ObservedAddresses does and returns them trimmed; an empty list is nil.
func CleanObservedAddresses(addresses []string) ([]string, error) {
	if len(addresses) == 0 {
		return nil, nil
	}
	if len(addresses) > MaxObservedAddresses {
		return nil, fmt.Errorf("observed_addresses names %d addresses; at most %d", len(addresses), MaxObservedAddresses)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(addresses))
	for _, raw := range addresses {
		address := strings.TrimSpace(raw)
		host, port, err := net.SplitHostPort(address)
		n, perr := strconv.Atoi(port)
		if err != nil || host == "" || perr != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("observed address %q is not host:port", raw)
		}
		if seen[address] {
			return nil, fmt.Errorf("observed address %q is listed twice", address)
		}
		seen[address] = true
		out = append(out, address)
	}
	return out, nil
}
