// SPDX-License-Identifier: BUSL-1.1

package secretscli

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/auditsink"
)

type memClient struct{ m map[string][]byte }

func (c *memClient) Fetch(_ context.Context, path string) ([]byte, error) {
	v, ok := c.m[path]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return v, nil
}
func (c *memClient) Set(_ context.Context, path string, value []byte) error {
	c.m[path] = value
	return nil
}

func TestInjectPutsSecretInEnvNotDisk(t *testing.T) {
	cli := New("t1", &memClient{m: map[string][]byte{}}, &auditsink.Recorder{})
	out, err := cli.Inject(context.Background(), map[string]string{"MYSECRET": "hunter2"},
		[]string{"sh", "-c", `printf %s "$MYSECRET"`})
	if err != nil {
		t.Fatalf("Inject: %v", err)
	}
	if strings.TrimSpace(string(out)) != "hunter2" {
		t.Errorf("child did not see injected secret via env: %q", out)
	}
}

func TestInjectAllowsExplicitTokenMapping(t *testing.T) {
	t.Setenv("TRSTCTL_TOKEN", "parent-bearer")
	cli := New("t1", &memClient{m: map[string][]byte{}}, &auditsink.Recorder{})
	out, err := cli.InjectBytes(context.Background(), map[string][]byte{"TRSTCTL_TOKEN": []byte("mapped-value")},
		[]string{"sh", "-c", `printf %s "$TRSTCTL_TOKEN"`})
	if err != nil {
		t.Fatalf("InjectBytes: %v", err)
	}
	if string(out) != "mapped-value" {
		t.Error("child did not receive the explicitly mapped value")
	}
}

// A257: WithoutEnv keeps the named variables out of the child too, while the
// unfiltered CLI still passes them on and both drop TRSTCTL_TOKEN.
func TestInjectWithoutEnvDropsNamedVariables(t *testing.T) {
	t.Setenv("TRSTCTL_TOKEN", "parent-bearer")
	t.Setenv("TRSTCTL_ADMIN_TOKEN", "admin-bearer")
	t.Setenv("KEEP_ME", "kept")
	script := []string{"sh", "-c", `printf '%s|%s|%s' "$TRSTCTL_TOKEN" "$TRSTCTL_ADMIN_TOKEN" "$KEEP_ME"`}
	plain := New("t1", nil, nil)
	out, err := plain.InjectBytes(context.Background(), nil, script)
	if err != nil || string(out) != "|admin-bearer|kept" {
		t.Fatalf("unfiltered child saw %q (%v)", out, err)
	}
	filtered := plain.WithoutEnv(func(name string) bool { return name == "TRSTCTL_ADMIN_TOKEN" })
	out, err = filtered.InjectBytes(context.Background(), nil, script)
	if err != nil || string(out) != "||kept" {
		t.Fatalf("filtered child saw %q (%v)", out, err)
	}
	if out, _ := plain.InjectBytes(context.Background(), nil, script); string(out) != "|admin-bearer|kept" {
		t.Fatalf("WithoutEnv changed the CLI it was called on: %q", out)
	}
}

func TestFetchSetRoundTrip(t *testing.T) {
	rec := &auditsink.Recorder{}
	cli := New("t1", &memClient{m: map[string][]byte{}}, rec)
	ctx := context.Background()
	if err := cli.Set(ctx, "app/db", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	got, err := cli.Fetch(ctx, "app/db")
	if err != nil || string(got) != "v1" {
		t.Fatalf("fetch = %q (err %v)", got, err)
	}
	if rec.Count("secretscli.set") != 1 || rec.Count("secretscli.fetch") != 1 {
		t.Error("set/fetch not audited")
	}
}
