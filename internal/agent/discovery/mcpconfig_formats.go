// SPDX-License-Identifier: BUSL-1.1

package discovery

import (
	"encoding/json"

	"trstctl.com/trstctl/internal/secretjson"
)

// TOML and YAML MCP client configuration (P7-L1) is read into the same server
// entries as JSON, each value a JSON string made from the value's bytes, so
// one describer classifies every format and every buffer is wiped the same
// way.

// mcpFormatServer is one server entry a TOML or YAML file names.
type mcpFormatServer struct {
	format string
	name   string
	entry  mcpServerEntry
}

// quoteRaw is value's bytes as a JSON string, in a new buffer.
func quoteRaw(value []byte) json.RawMessage {
	return json.RawMessage(secretjson.QuoteBytes(value))
}

// tomlMCPServers reads [mcp_servers.<name>] tables: command, args, env, url,
// http_headers (or headers), type and transport.
func tomlMCPServers(pairs []tomlPair) []mcpFormatServer {
	index := map[string]int{}
	var out []mcpFormatServer
	for _, p := range pairs {
		if len(p.key) < 3 || len(p.key) > 4 || p.key[0] != "mcp_servers" {
			continue
		}
		name, field := p.key[1], p.key[2]
		at, ok := index[name]
		if !ok {
			at = len(out)
			index[name] = at
			out = append(out, mcpFormatServer{format: "mcp_servers", name: name})
		}
		e := &out[at].entry
		if len(p.key) == 4 {
			if !p.val.isString {
				continue
			}
			switch field {
			case "env":
				if e.Env == nil {
					e.Env = map[string]json.RawMessage{}
				}
				e.Env[p.key[3]] = quoteRaw(p.val.bytes)
			case "http_headers", "headers":
				if e.Headers == nil {
					e.Headers = map[string]json.RawMessage{}
				}
				e.Headers[p.key[3]] = quoteRaw(p.val.bytes)
			}
			continue
		}
		if field == "args" && p.val.isArray {
			for _, item := range p.val.items {
				if item.isString {
					e.Args = append(e.Args, quoteRaw(item.bytes))
				} else {
					e.Args = append(e.Args, json.RawMessage("null"))
				}
			}
			continue
		}
		if !p.val.isString {
			continue
		}
		switch field {
		case "command":
			e.Command = quoteRaw(p.val.bytes)
		case "url":
			e.URL = quoteRaw(p.val.bytes)
		case "type":
			e.Type = quoteRaw(p.val.bytes)
		case "transport":
			e.Transport = quoteRaw(p.val.bytes)
		}
	}
	return out
}

// yamlMCPServers reads an mcpServers, mcp_servers or servers mapping (or
// mcp.servers): name to entry, or a sequence of entries that each carry a
// name.
func yamlMCPServers(root *yamlNode) []mcpFormatServer {
	var out []mcpFormatServer
	add := func(format string, n *yamlNode) {
		switch {
		case n == nil:
		case n.kind == 'm':
			for i, name := range n.keys {
				if e, ok := yamlMCPEntry(n.values[i]); ok {
					out = append(out, mcpFormatServer{format: format, name: name, entry: e})
				}
			}
		case n.kind == 's':
			for _, item := range n.items {
				name := item.get("name")
				if name == nil || name.kind != 'v' || len(name.scalar) == 0 {
					continue
				}
				if e, ok := yamlMCPEntry(item); ok {
					out = append(out, mcpFormatServer{format: format, name: string(name.scalar), entry: e})
				}
			}
		}
	}
	for _, key := range []string{"mcpServers", "mcp_servers", "servers"} {
		add(key, root.get(key))
	}
	add("mcp.servers", root.get("mcp").get("servers"))
	return out
}

// yamlMCPEntry reads one server entry's fields (command or cmd, args, env or
// envs, url, uri or serverUrl, headers, type and transport).
func yamlMCPEntry(n *yamlNode) (mcpServerEntry, bool) {
	if n == nil || n.kind != 'm' {
		return mcpServerEntry{}, false
	}
	scalar := func(keys ...string) json.RawMessage {
		for _, key := range keys {
			if v := n.get(key); v != nil && v.kind == 'v' && len(v.scalar) > 0 {
				return quoteRaw(v.scalar)
			}
		}
		return nil
	}
	table := func(keys ...string) map[string]json.RawMessage {
		for _, key := range keys {
			if v := n.get(key); v != nil && v.kind == 'm' {
				out := map[string]json.RawMessage{}
				for i, k := range v.keys {
					if v.values[i] != nil && v.values[i].kind == 'v' {
						out[k] = quoteRaw(v.values[i].scalar)
					}
				}
				return out
			}
		}
		return nil
	}
	e := mcpServerEntry{
		Command: scalar("command", "cmd"), URL: scalar("url", "uri"), ServerURL: scalar("serverUrl"),
		Type: scalar("type"), Transport: scalar("transport"),
		Env: table("env", "envs"), Headers: table("headers"),
	}
	if args := n.get("args"); args != nil && args.kind == 's' {
		for _, item := range args.items {
			if item != nil && item.kind == 'v' {
				e.Args = append(e.Args, quoteRaw(item.scalar))
			} else {
				e.Args = append(e.Args, json.RawMessage("null"))
			}
		}
	}
	return e, true
}
