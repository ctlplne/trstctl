// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/pluginhost"
	"trstctl.com/trstctl/internal/pluginhost/wasmgen"
)

// The connector library on the relay (A242): a module runs only with a signed
// manifest its operator approved, under exactly the grant it declared, on its
// own bounded pool, and every failure names what the host observed.

// dialGrant is the operator grant these modules run under.
func dialGrant() pluginhost.Grant {
	return pluginhost.NewGrant(pluginhost.CapNetDial).WithPathPrefix(pluginhost.CapNetDial, "appliance.internal:443")
}

var dialPerms = pluginhost.Permissions{Capabilities: []string{"net.dial"}}

// statusModule exports deploy, run and readback, each returning a constant or
// running a raw failure body.
func statusModule(deploy, readback wasmgen.Export) []byte {
	deploy.Name, readback.Name = "deploy", "readback"
	return wasmgen.Module("cap_dial", 2, nil, []wasmgen.Export{{Name: "run", Const: 0}, deploy, readback})
}

func loadRuntime(t *testing.T, dir string, keyPEM []byte) *relay.PluginRuntime {
	t.Helper()
	rt, err := relay.NewPluginRuntime(context.Background(), relay.PluginConfig{
		Dir: dir, TrustedKeyPEMs: [][]byte{keyPEM}, Grant: dialGrant(), ApprovalsPath: approvalsPath(dir),
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(func() { _ = rt.Close(context.Background()) })
	return rt
}

func moduleState(t *testing.T, rt *relay.PluginRuntime, name string) relay.ModuleStatus {
	t.Helper()
	for _, st := range rt.Modules() {
		if st.Name == name {
			return st
		}
	}
	t.Fatalf("no status for %s in %+v", name, rt.Modules())
	return relay.ModuleStatus{}
}

// A242: a module ships a manifest signed by its own publisher that names this
// exact build; anything else fails the load like a bad signature does.
func TestAModuleNeedsItsOwnSignedManifestA242(t *testing.T) {
	ctx := context.Background()
	module := statusModule(wasmgen.Export{Const: 0}, wasmgen.Export{Const: 0})
	for name, spoil := range map[string]func(dir string, sign func([]byte) []byte){
		"no manifest": func(dir string, _ func([]byte) []byte) {
			_ = os.Remove(filepath.Join(dir, "partner.manifest.json"))
		},
		"unsigned manifest": func(dir string, _ func([]byte) []byte) {
			_ = os.Remove(filepath.Join(dir, "partner.manifest.json.sig"))
		},
		"another build": func(dir string, sign func([]byte) []byte) {
			writeManifest(t, dir, "partner", []byte("another module"), "1.0.0", dialPerms, sign)
		},
		"another publisher": func(dir string, _ func([]byte) []byte) {
			_, other, err := crypto.GenerateEd25519KeyPair()
			if err != nil {
				t.Fatal(err)
			}
			writeManifest(t, dir, "partner", module, "1.0.0", dialPerms, other)
		},
	} {
		dir, keyPEM, sign := signedPluginDir(t, "partner", module, pluginhost.CapNetDial)
		spoil(dir, sign)
		rt, err := relay.NewPluginRuntime(ctx, relay.PluginConfig{
			Dir: dir, TrustedKeyPEMs: [][]byte{keyPEM}, Grant: dialGrant(), ApprovalsPath: approvalsPath(dir),
		})
		if err == nil {
			_ = rt.Close(ctx)
			t.Errorf("%s: the module loaded", name)
		}
	}
}

// A242: a module no approval covers is verified, reported with what an
// approval would grant, and refused before anything is redeemed. An upgrade
// that asks for no more runs under the existing approval; one that asks for
// more, is older, or needs more than the relay's grant waits.
func TestAModuleRunsOnlyUnderItsOperatorsApprovalA242(t *testing.T) {
	module := statusModule(wasmgen.Export{Const: 0}, wasmgen.Export{Const: 0})
	dir, keyPEM, sign := signedPluginDir(t, "partner", module, pluginhost.CapNetDial)
	if err := os.Remove(approvalsPath(dir)); err != nil {
		t.Fatal(err)
	}

	rt := loadRuntime(t, dir, keyPEM)
	st := moduleState(t, rt, "partner")
	var failure *relay.ModuleFailure
	switch {
	case st.State != relay.ModuleAwaitingApproval || !reflect.DeepEqual(st.Diff, []string{"capability net.dial"}):
		t.Fatalf("an unapproved module: %+v", st)
	case !rt.Has("partner") || len(rt.Names()) != 0:
		t.Fatal("an unapproved module is loaded")
	case len(rt.Census()) != 1 || len(rt.Census()[0].Grants) != 0 || rt.Census()[0].Module == nil ||
		rt.Census()[0].Module.State != relay.ModuleAwaitingApproval ||
		!reflect.DeepEqual(rt.Census()[0].Module.PendingPermissions, []string{"capability net.dial"}):
		t.Fatalf("the census does not report the module as awaiting approval with no grants: %+v", rt.Census())
	case !errors.As(rt.Ready("partner"), &failure) || failure.Class != relay.ModuleAwaitingApproval:
		t.Fatalf("Ready = %v", rt.Ready("partner"))
	}
	ch := &fakeChannel{jobs: []relay.Job{intentJob(t, 1, relay.DeployIntent{Connector: "partner", Target: "lb"})}}
	if _, err := relay.RunOnceWithRoles(context.Background(), ch, http.DefaultClient, connector.LocalOpsConfig{}, rt, nil, nil, nil, 4, 60); err != nil {
		t.Fatal(err)
	}
	if ch.redeemed != 0 || len(ch.reports) != 1 || ch.reports[0].outcome != relay.OutcomeFailed ||
		!strings.Contains(ch.reports[0].detail, "awaits its operator's approval") {
		t.Fatalf("a deploy to an unapproved module: redeemed %d, reports %+v", ch.redeemed, ch.reports)
	}

	if err := relay.ApproveModule(approvalsPath(dir), st, time.Now()); err != nil {
		t.Fatal(err)
	}
	if st := moduleState(t, loadRuntime(t, dir, keyPEM), "partner"); st.State != relay.ModuleLoaded {
		t.Fatalf("the approved module: %+v", st)
	}

	// A newer build asking for the same: runs under the approval.
	upgrade := statusModule(wasmgen.Export{Const: 0}, wasmgen.Export{Const: 1})
	writeModule(t, dir, "partner", upgrade, sign(upgrade))
	writeManifest(t, dir, "partner", upgrade, "1.1.0", dialPerms, sign)
	if st := moduleState(t, loadRuntime(t, dir, keyPEM), "partner"); st.State != relay.ModuleLoaded {
		t.Fatalf("a same-permission upgrade: %+v", st)
	}
	// A newer build asking for a credential: waits, naming it.
	writeManifest(t, dir, "partner", upgrade, "1.2.0",
		pluginhost.Permissions{Capabilities: []string{"net.dial"}, Credentials: []string{"bearer"}}, sign)
	if st := moduleState(t, loadRuntime(t, dir, keyPEM), "partner"); st.State != relay.ModuleAwaitingApproval ||
		!reflect.DeepEqual(st.Diff, []string{"credential bearer"}) {
		t.Fatalf("a widening upgrade: %+v", st)
	}
	// An older build: waits.
	writeManifest(t, dir, "partner", upgrade, "0.9.0", dialPerms, sign)
	if st := moduleState(t, loadRuntime(t, dir, keyPEM), "partner"); st.State != relay.ModuleAwaitingApproval ||
		!strings.Contains(st.Reason, "older") {
		t.Fatalf("a downgrade: %+v", st)
	}
	// More than the relay's grant: incompatible, and no approval changes that.
	writeManifest(t, dir, "partner", upgrade, "2.0.0",
		pluginhost.Permissions{Capabilities: []string{"net.dial", "fs.write"}}, sign)
	st = moduleState(t, loadRuntime(t, dir, keyPEM), "partner")
	if st.State != relay.ModuleIncompatible || relay.ApproveModule(approvalsPath(dir), st, time.Now()) == nil {
		t.Fatalf("a module beyond the relay's grant: %+v", st)
	}
}

// A242: a module that spins or floods occupies its own pool and its own time
// limit, never another module's workers.
func TestASpinningModuleCannotStarveAnotherA242(t *testing.T) {
	ctx := context.Background()
	spinner := statusModule(wasmgen.Export{Raw: wasmgen.Spin}, wasmgen.Export{Const: 0})
	steady := statusModule(wasmgen.Export{Const: 0}, wasmgen.Export{Const: 0})
	dir, keyPEM, sign := signedPluginDir(t, "spinner", spinner, pluginhost.CapNetDial)
	writeModule(t, dir, "steady", steady, sign(steady))
	writeManifest(t, dir, "steady", steady, "1.0.0", dialPerms, sign)
	approve(t, dir, "steady", "1.0.0", steady, keyPEM, dialPerms)
	// The spinner declares a 300 ms call limit.
	raw := writeManifest(t, dir, "spinner", spinner, "1.0.0", dialPerms, sign)
	raw = []byte(strings.Replace(string(raw), `"revocation":"delete"`, `"revocation":"delete","limits":{"timeout_ms":300}`, 1))
	if err := os.WriteFile(filepath.Join(dir, "spinner.manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "spinner.manifest.json.sig"), sign(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	rt := loadRuntime(t, dir, keyPEM)

	var wg sync.WaitGroup
	classes := make(chan string, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var failure *relay.ModuleFailure
			if err := rt.Deploy(ctx, "spinner", relay.PluginCall{}); errors.As(err, &failure) {
				classes <- failure.Class
			} else {
				classes <- "unexpected"
			}
		}()
	}
	time.Sleep(50 * time.Millisecond) // the spinner's pool is full and its queue is refusing
	start := time.Now()
	if err := rt.Deploy(ctx, "steady", relay.PluginCall{}); err != nil {
		t.Fatalf("the steady module failed beside a spinning one: %v", err)
	}
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the steady module waited %s behind a spinning one", took)
	}
	wg.Wait()
	close(classes)
	seen := map[string]int{}
	for class := range classes {
		seen[class]++
	}
	if seen[pluginhost.FailureTimeout] == 0 || seen[pluginhost.FailureRejected] == 0 || seen["unexpected"] != 0 {
		t.Fatalf("the spinner's calls ended as %v; want timeouts at its limit and the overflow refused", seen)
	}
	health := moduleState(t, rt, "spinner").Health
	if health.Calls != 32 || health.ConsecutiveFailures != 32 || health.ByClass[pluginhost.FailureTimeout] != int64(seen[pluginhost.FailureTimeout]) {
		t.Fatalf("spinner health = %+v", health)
	}
	if steadyHealth := moduleState(t, rt, "steady").Health; steadyHealth.Calls != 1 || steadyHealth.Failures != 0 {
		t.Fatalf("steady health = %+v", steadyHealth)
	}
}

// A242: a crash, a refused operation or a failure status reaches the control
// plane as exact evidence (the module's name, version and digest, the entry
// point and the class) while the job's intent stays queued for its retry. A
// create-new module's retry asks its readback first and does not repeat a
// deploy that already landed.
func TestModuleFailuresKeepTheIntentAndExactEvidenceA242(t *testing.T) {
	ctx := context.Background()
	material := map[string][]byte{"credential.cert_pem": []byte(testCertPEM)}
	run := func(rt *relay.PluginRuntime, attempt int) *fakeChannel {
		t.Helper()
		job := intentJob(t, 7, relay.DeployIntent{Connector: "partner", Target: "lb", Fingerprint: "ff00"})
		job.Attempt = attempt
		ch := &fakeChannel{jobs: []relay.Job{job}, material: material}
		if _, err := relay.RunOnceWithRoles(ctx, ch, http.DefaultClient, connector.LocalOpsConfig{}, rt, nil, nil, nil, 4, 60); err != nil {
			t.Fatal(err)
		}
		if len(ch.reports) != 1 {
			t.Fatalf("reports = %+v", ch.reports)
		}
		return ch
	}
	for _, tc := range []struct {
		name   string
		deploy wasmgen.Export
		want   string
	}{
		{"trap", wasmgen.Export{Raw: wasmgen.Trap}, "deploy failed: trap"},
		{"status", wasmgen.Export{Const: 3}, "deploy returned status 3"},
		{"out of grant", wasmgen.Export{Args: []int32{0, 0}}, "deploy attempted 1 operation(s) outside its capability grant"},
	} {
		module := statusModule(tc.deploy, wasmgen.Export{Const: 0})
		dir, keyPEM, _ := signedPluginDir(t, "partner", module, pluginhost.CapNetDial)
		ch := run(loadRuntime(t, dir, keyPEM), 1)
		want := "connector module partner 1.0.0 (sha256:" + crypto.SHA256Hex(module) + ") " + tc.want
		if ch.reports[0].outcome != relay.OutcomeFailed || ch.reports[0].detail != want || ch.redeemed != 1 {
			t.Errorf("%s: report %+v, want failed %q", tc.name, ch.reports[0], want)
		}
	}

	// create-new: the deploy traps (it would make a duplicate); readback says
	// the earlier attempt landed.
	module := statusModule(wasmgen.Export{Raw: wasmgen.Trap}, wasmgen.Export{Const: 0})
	dir, keyPEM, sign := signedPluginDir(t, "partner", module, pluginhost.CapNetDial)
	raw := writeManifest(t, dir, "partner", module, "1.0.0", dialPerms, sign)
	raw = []byte(strings.Replace(string(raw), `"replace-by-name"`, `"create-new"`, 1))
	if err := os.WriteFile(filepath.Join(dir, "partner.manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "partner.manifest.json.sig"), sign(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	rt := loadRuntime(t, dir, keyPEM)
	if first := run(rt, 1); first.reports[0].outcome != relay.OutcomeFailed {
		t.Fatalf("the first attempt did not run the deploy: %+v", first.reports[0])
	}
	if retry := run(rt, 2); retry.reports[0].outcome == relay.OutcomeFailed {
		t.Fatalf("the retry repeated a deploy its readback says landed: %+v", retry.reports[0])
	}
	if health := moduleState(t, rt, "partner").Health; health.ByClass[pluginhost.FailureTrap] != 1 {
		t.Fatalf("the retry ran the deploy again: %+v", health)
	}
}
