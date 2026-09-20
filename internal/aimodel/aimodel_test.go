// SPDX-License-Identifier: BUSL-1.1

package aimodel

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type captureModel struct {
	name string
	seen string
}

func (m *captureModel) Name() string { return m.name }
func (m *captureModel) Complete(_ context.Context, prompt string) (string, error) {
	m.seen = prompt
	return "answer from " + m.name, nil
}

func TestSameCallCloudAndLocal(t *testing.T) {
	ctx := context.Background()
	cloud := New(&captureModel{name: "cloud"}, nil)
	local := New(&captureModel{name: "local"}, nil)
	for _, a := range []*Adapter{cloud, local} {
		out, err := a.Reason(ctx, "explain this incident")
		if err != nil || !strings.HasPrefix(out, "answer from ") {
			t.Fatalf("reason(%s) = %q (err %v)", a.ModelName(), out, err)
		}
	}
}

func TestGracefulDegradationNoModel(t *testing.T) {
	a := New(nil, nil)
	if a.Available() {
		t.Error("Available() true with no model")
	}
	if _, err := a.Reason(context.Background(), "x"); !errors.Is(err, ErrNoModel) {
		t.Errorf("Reason with no model = %v, want ErrNoModel", err)
	}
}

func TestNoKeyMaterialReachesModelBoundary(t *testing.T) {
	cm := &captureModel{name: "cloud"}
	a := New(cm, nil)
	prompt := "context:\n-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIKx...secretbytes...\n-----END EC PRIVATE KEY-----\npassword=hunter2\nplease explain"
	if _, err := a.Reason(context.Background(), prompt); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cm.seen, "BEGIN EC PRIVATE KEY") || strings.Contains(cm.seen, "hunter2") {
		t.Errorf("key/secret material reached the model boundary:\n%s", cm.seen)
	}
	if !strings.Contains(cm.seen, "[REDACTED") {
		t.Error("redaction marker missing")
	}
}
