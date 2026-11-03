// SPDX-License-Identifier: BUSL-1.1

package relay

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"trstctl.com/trstctl/internal/pluginhost"
)

// The connector module conformance kit (A242): what a publisher runs before
// shipping a module and an operator runs before approving one. It checks
// everything the relay checks at load, and then what load cannot: that every
// declared action is exported, and that the module's test runs read-only and
// inside its grant against a stand-in target. It never needs an approval and
// records none.

// ModuleCheck is one module's conformance result.
type ModuleCheck struct {
	Name    string
	Version string
	Digest  string
	// State and Reason are what this relay would do with the module today.
	State  string
	Reason string
	Diff   []string
	Checks []pluginhost.Check
}

// OK reports whether every check passed.
func (c ModuleCheck) OK() bool {
	for _, check := range c.Checks {
		if !check.Passed {
			return false
		}
	}
	return len(c.Checks) > 0
}

// exportFor is the export each manifest action needs.
var exportFor = map[string][]string{
	"deploy":   {"deploy", "run"},
	"test":     {"test"},
	"readback": {"readback"},
	"rollback": {"rollback"},
	"revoke":   {"revoke"},
}

// CheckModules runs the kit against every module in cfg.Dir under cfg's trust
// keys and grant.
func CheckModules(ctx context.Context, cfg PluginConfig) ([]ModuleCheck, error) {
	if strings.TrimSpace(cfg.Dir) == "" {
		return nil, ErrPluginsNotConfigured
	}
	trust, err := pluginhost.NewTrustPolicy(cfg.TrustedKeyPEMs, cfg.PinnedDigestsHex)
	if err != nil {
		return nil, fmt.Errorf("relay: plugin trust policy: %w", err)
	}
	approvals, err := ReadModuleApprovals(cfg.ApprovalsPath)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(cfg.Dir)
	if err != nil {
		return nil, fmt.Errorf("relay: read plugin directory: %w", err)
	}
	var out []ModuleCheck
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".wasm") {
			continue
		}
		out = append(out, checkModule(ctx, trust, cfg, strings.TrimSuffix(entry.Name(), ".wasm"), approvals))
	}
	return out, nil
}

func checkModule(ctx context.Context, trust *pluginhost.TrustPolicy, cfg PluginConfig, name string, approvals map[string]ModuleApproval) ModuleCheck {
	c := ModuleCheck{Name: name}
	add := func(check string, err error) bool {
		detail := ""
		if err != nil {
			detail = err.Error()
		}
		c.Checks = append(c.Checks, pluginhost.Check{Name: check, Passed: err == nil, Detail: detail})
		return err == nil
	}
	v, err := verifyModule(trust, cfg.Dir, name)
	if !add("signed by a trusted publisher, with a manifest it signed for this build", err) {
		return c
	}
	c.Version, c.Digest = v.manifest.Version, v.provenance.Digest
	st := v.status(cfg.Grant, approvals[name])
	c.State, c.Reason, c.Diff = st.State, st.Reason, st.Diff
	if !add(fmt.Sprintf("supports host ABI %d", pluginhost.HostAPIVersion), boolErr(v.manifest.SupportsHost(),
		fmt.Sprintf("it supports %d to %d", v.manifest.HostAPI.Min, v.manifest.HostAPI.Max))) {
		return c
	}
	_, grantErr := pluginhost.EffectiveGrant(cfg.Grant, v.manifest)
	if !add("asks for no more than this relay's grant", grantErr) {
		return c
	}
	m, err := v.load(ctx, trust, cfg.Grant)
	if !add("loads under its own grant and limits", err) {
		return c
	}
	defer m.close(ctx)
	var missing []string
	for _, action := range v.manifest.Actions {
		exported := false
		for _, fn := range exportFor[action] {
			exported = exported || m.plugin.HasExport(fn)
		}
		if !exported {
			missing = append(missing, action)
		}
	}
	add("exports every action it declares", boolErr(len(missing) == 0, "declared but not exported: "+strings.Join(missing, ", ")))
	if v.manifest.Has("test") && m.plugin.HasExport("test") {
		add("test runs read-only and inside its grant against a stand-in target", standInTest(ctx, m))
	}
	return c
}

// standInTest runs the module's test entry point read-only against a target
// that answers every request 200 with an empty JSON object. A status the
// module returns is its business (a stand-in is not its appliance); a trap, a
// timeout or an operation outside its grant is not.
func standInTest(ctx context.Context, m *pluginModule) error {
	before := m.plugin.Stats()
	_, err := m.host.InvokeWith(ctx, m.plugin, "test", pluginhost.Invocation{
		Inputs: map[string][]byte{
			"fingerprint": []byte("00"), "target": []byte("stand-in"), "target_config": []byte("{}"),
			"certificate_pem": []byte("stand-in certificate"),
		},
		ReadOnly: true,
		HTTP: func(context.Context, pluginhost.HTTPRequest) (pluginhost.HTTPResponse, error) {
			return pluginhost.HTTPResponse{Status: 200, Body: "{}", Headers: map[string]string{"Content-Type": "application/json"}}, nil
		},
	})
	if err != nil {
		return fmt.Errorf("the test call failed: %s", pluginhost.FailureClass(err))
	}
	if denied := m.plugin.Stats().Denied - before.Denied; denied > 0 {
		return fmt.Errorf("the test attempted %d operation(s) outside its grant or its read-only mode", denied)
	}
	return nil
}

func boolErr(ok bool, detail string) error {
	if ok {
		return nil
	}
	return errors.New(detail)
}
