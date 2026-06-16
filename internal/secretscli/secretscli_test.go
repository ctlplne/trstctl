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
