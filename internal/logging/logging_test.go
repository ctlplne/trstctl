package logging_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/logging"
)

func TestJSONHasConsistentFields(t *testing.T) {
	var buf bytes.Buffer
	logger, err := logging.New(logging.Options{Level: "info", Format: "json", Service: "trstctl"}, &buf)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.Info("hello", "request_id", "abc")

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, buf.String())
	}
	for _, k := range []string{"time", "level", "msg", "service", "request_id"} {
		if _, ok := rec[k]; !ok {
			t.Errorf("missing field %q in %v", k, rec)
		}
	}
	if rec["msg"] != "hello" || rec["service"] != "trstctl" || rec["request_id"] != "abc" {
		t.Errorf("unexpected field values: %v", rec)
	}
	if lvl, _ := rec["level"].(string); !strings.EqualFold(lvl, "info") {
		t.Errorf("level = %v, want INFO", rec["level"])
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger, err := logging.New(logging.Options{Level: "info", Format: "json"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	logger.Debug("filtered out")
	if buf.Len() != 0 {
		t.Errorf("debug must be filtered at info level, got: %s", buf.String())
	}
	logger.Warn("should appear")
	if !strings.Contains(buf.String(), "should appear") {
		t.Errorf("warn should appear, got: %s", buf.String())
	}
}

func TestTextFormat(t *testing.T) {
	var buf bytes.Buffer
	logger, err := logging.New(logging.Options{Level: "debug", Format: "text"}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("hi there")
	out := buf.String()
	if !strings.Contains(out, "hi there") {
		t.Errorf("text output should contain the message: %s", out)
	}
	if strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("text output should not be JSON: %s", out)
	}
}

func TestInvalidLevelAndFormat(t *testing.T) {
	var buf bytes.Buffer
	if _, err := logging.New(logging.Options{Level: "loud", Format: "json"}, &buf); err == nil {
		t.Error("expected an error for an invalid level")
	}
	if _, err := logging.New(logging.Options{Level: "info", Format: "yaml"}, &buf); err == nil {
		t.Error("expected an error for an invalid format")
	}
}
