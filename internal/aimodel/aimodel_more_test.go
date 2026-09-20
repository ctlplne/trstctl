// SPDX-License-Identifier: BUSL-1.1

package aimodel

import (
	"context"
	"strings"
	"testing"
)

type stubCompleter struct{ seen string }

func (c *stubCompleter) Do(_ context.Context, prompt string) (string, error) {
	c.seen = prompt
	return "done", nil
}

func TestCloudAndLocalProviderShape(t *testing.T) {
	cc := &stubCompleter{}
	cm := CloudModel{Provider: "anthropic", Client: cc}
	if cm.Name() != "cloud:anthropic" {
		t.Errorf("cloud name = %q", cm.Name())
	}
	if out, _ := cm.Complete(context.Background(), "hi"); out != "done" || cc.seen != "hi" {
		t.Errorf("cloud complete out=%q seen=%q", out, cc.seen)
	}
	lc := &stubCompleter{}
	lm := LocalModel{Runtime: "ollama", Client: lc}
	if lm.Name() != "local:ollama" {
		t.Errorf("local name = %q", lm.Name())
	}
	_, _ = lm.Complete(context.Background(), "yo")
	if lc.seen != "yo" {
		t.Errorf("local seen = %q", lc.seen)
	}
}

func TestRedactorCoversPatterns(t *testing.T) {
	cases := []string{"api_key=ABCDEF123", "token: abcdef", "password=hunter2", "secret = s3"}
	for _, c := range cases {
		if !strings.Contains(DefaultRedactor(c), "[REDACTED") {
			t.Errorf("not redacted: %q -> %q", c, DefaultRedactor(c))
		}
	}
	long := "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5QUJD"
	if strings.Contains(DefaultRedactor(long), "YWJjZ") {
		t.Error("long base64 (likely key material) not redacted")
	}
}

func TestAdapterRedactAndModelName(t *testing.T) {
	a := New(nil, nil)
	if a.ModelName() != "" {
		t.Errorf("no-model ModelName = %q, want empty", a.ModelName())
	}
	if !strings.Contains(a.Redact("password=x"), "[REDACTED") {
		t.Error("Redact did not apply the boundary redactor")
	}
	withModel := New(&stubCompleterModel{}, nil)
	if withModel.ModelName() != "stub" {
		t.Errorf("ModelName = %q", withModel.ModelName())
	}
}

type stubCompleterModel struct{}

func (stubCompleterModel) Name() string                                     { return "stub" }
func (stubCompleterModel) Complete(context.Context, string) (string, error) { return "x", nil }
