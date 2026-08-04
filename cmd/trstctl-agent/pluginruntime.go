// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/pluginhost"
)

// Assembling the relay's third-party connector runtime from operator input
// (epic E4).
//
// Every input here comes from the operator's own command line: which modules,
// which publisher keys vouch for them, which exact builds, and what those
// modules are allowed to do. None of it is read from the module, and none of it
// arrives from the control plane.
//
// That is the point. A grant derived from a module's own metadata would let a
// publisher widen their privileges by editing a file they ship; a grant pushed
// from the control plane would mean the vendor decides what partner code may do
// inside a customer's network. Both make the capability system decorative. The
// person who owns the machine decides what runs on it.

// buildPluginRuntime constructs the relay's plugin runtime, or nil when third-
// party connectors are not configured.
//
// A configuration error is FATAL rather than a warning. An agent that came up
// having silently skipped its plugin directory would serve a subset of the
// connectors an operator configured, and the missing one is exactly the one
// whose signature did not check out.
func buildPluginRuntime(ctx context.Context, o agentOptions) (*relay.PluginRuntime, error) {
	dir := strings.TrimSpace(o.pluginDir)
	if dir == "" {
		return nil, nil
	}
	keys, err := readPluginKeys(o.pluginKeys)
	if err != nil {
		return nil, err
	}
	grant, err := buildPluginGrant(o.pluginCaps, o.pluginCapPrefix)
	if err != nil {
		return nil, err
	}
	rt, err := relay.NewPluginRuntime(ctx, relay.PluginConfig{
		Dir:              dir,
		TrustedKeyPEMs:   keys,
		PinnedDigestsHex: splitList(o.pluginPins),
		Grant:            grant,
	})
	if err != nil {
		return nil, err
	}
	if rt != nil {
		names := rt.Names()
		pluginConnectorCount.Store(int64(len(names)))
		fmt.Printf("trstctl-agent: third-party connectors loaded and verified: %v\n", names)
	}
	return rt, nil
}

// readPluginKeys loads the publisher public keys from disk.
func readPluginKeys(list string) ([][]byte, error) {
	paths := splitList(list)
	if len(paths) == 0 {
		return nil, fmt.Errorf("trstctl-agent: --connector-plugin-dir is set but --connector-plugin-key " +
			"is not; this agent will not load third-party code it cannot verify")
	}
	out := make([][]byte, 0, len(paths))
	for _, path := range paths {
		pem, err := os.ReadFile(path) // #nosec G304 -- operator-supplied trust key path (CWE-22)
		if err != nil {
			return nil, fmt.Errorf("trstctl-agent: read connector plugin key %q: %w", path, err)
		}
		out = append(out, pem)
	}
	return out, nil
}

// buildPluginGrant turns the operator's capability flags into a grant.
//
// A capability named with no prefix is unrestricted FOR THAT CAPABILITY, which
// is a deliberate and visible choice on a command line rather than a default.
// A prefix naming a capability that was not granted is an error: it reads as a
// restriction and would silently be none, which is the shape of mistake this
// whole subsystem exists to make impossible.
func buildPluginGrant(caps, prefixes string) (pluginhost.Grant, error) {
	names := splitList(caps)
	if len(names) == 0 {
		return pluginhost.Grant{}, fmt.Errorf("trstctl-agent: --connector-plugin-dir is set but " +
			"--connector-plugin-capability is not; third-party connectors run under a grant the " +
			"operator states explicitly, never a default")
	}
	granted := make([]pluginhost.Capability, 0, len(names))
	known := map[string]bool{}
	for _, name := range names {
		cap, ok := pluginCapability(name)
		if !ok {
			return pluginhost.Grant{}, fmt.Errorf("trstctl-agent: unknown connector plugin capability %q", name)
		}
		granted = append(granted, cap)
		known[name] = true
	}
	grant := pluginhost.NewGrant(granted...)
	for _, raw := range splitList(prefixes) {
		name, prefix, ok := strings.Cut(raw, "=")
		if !ok {
			return pluginhost.Grant{}, fmt.Errorf("trstctl-agent: connector plugin capability "+
				"prefix %q is not capability=prefix", raw)
		}
		name = strings.TrimSpace(name)
		if !known[name] {
			return pluginhost.Grant{}, fmt.Errorf("trstctl-agent: capability prefix names %q, which "+
				"is not in --connector-plugin-capability; it would read as a restriction and be none", name)
		}
		cap, _ := pluginCapability(name)
		grant = grant.WithPathPrefix(cap, strings.TrimSpace(prefix))
	}
	return grant, nil
}

// pluginCapability maps an operator-facing name to a capability.
func pluginCapability(name string) (pluginhost.Capability, bool) {
	switch strings.TrimSpace(name) {
	case "fs.read":
		return pluginhost.CapFSRead, true
	case "fs.write":
		return pluginhost.CapFSWrite, true
	case "net.dial":
		return pluginhost.CapNetDial, true
	default:
		return "", false
	}
}
