package config_test

import (
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// TestRateLimitDefaults: the per-tenant rate limiter ships on, with a sane limit.
func TestRateLimitDefaults(t *testing.T) {
	c := config.Default()
	if !c.RateLimit.Enabled {
		t.Error("rate limiting should be enabled by default (the product ships with backpressure)")
	}
	if c.RateLimit.Requests <= 0 {
		t.Errorf("default rate_limit.requests = %d, want positive", c.RateLimit.Requests)
	}
	if c.RateLimit.Window == "" {
		t.Error("default rate_limit.window must be set")
	}
	if _, err := c.RateLimit.WindowDuration(); err != nil {
		t.Errorf("default window must parse: %v", err)
	}
}

// TestRateLimitEnvOverrides: the limiter is configurable from the environment.
func TestRateLimitEnvOverrides(t *testing.T) {
	env := map[string]string{
		"TRSTCTL_POSTGRES_MODE":       "external",
		"TRSTCTL_POSTGRES_DSN":        "postgres://u:p@h:5432/db?sslmode=require",
		"TRSTCTL_NATS_MODE":           "external",
		"TRSTCTL_NATS_URL":            "nats://h:4222",
		"TRSTCTL_RATE_LIMIT_ENABLED":  "false",
		"TRSTCTL_RATE_LIMIT_REQUESTS": "50",
		"TRSTCTL_RATE_LIMIT_WINDOW":   "30s",
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.RateLimit.Enabled {
		t.Error("TRSTCTL_RATE_LIMIT_ENABLED=false should disable the limiter")
	}
	if cfg.RateLimit.Requests != 50 || cfg.RateLimit.Window != "30s" {
		t.Errorf("rate limit env not applied: %+v", cfg.RateLimit)
	}
}

// TestRateLimitValidated: a malformed window or non-positive request count fails
// fast.
func TestRateLimitValidated(t *testing.T) {
	base := map[string]string{
		"TRSTCTL_POSTGRES_MODE": "external",
		"TRSTCTL_POSTGRES_DSN":  "postgres://u:p@h:5432/db?sslmode=require",
		"TRSTCTL_NATS_MODE":     "external",
		"TRSTCTL_NATS_URL":      "nats://h:4222",
	}
	bad := map[string]string{"TRSTCTL_RATE_LIMIT_WINDOW": "not-a-duration"}
	if _, err := config.Load(envFunc(base, bad)); err == nil {
		t.Error("a malformed rate_limit.window should fail validation")
	}
}

func envFunc(maps ...map[string]string) func(string) string {
	return func(k string) string {
		for _, m := range maps {
			if v, ok := m[k]; ok {
				return v
			}
		}
		return ""
	}
}
